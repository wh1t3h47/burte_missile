# burte_missile
<div align="center">
  <img alt="Python" src="https://img.shields.io/badge/python-%2314354C.svg?style=for-the-badge&logo=python&logoColor=yellow"/>
  <img alt="Markdown" src="https://img.shields.io/badge/markdown-%23000000.svg?style=for-the-badge&logo=markdown&logoColor=white"/>
</div>

> By wh1t3h47 (Antônio M4rtos H4rres) - github.com/wh1t3h47

Tool to bruteforce a User-Password-Company login using libcurl, it tries to parametrize as much as possible in order to be useful for a lot of sites and quickly adaptable for your needs

## Example Usage
```shell
python3 ./main.py -h
```

## Limitations
```
Memory leaks occur, they may be due to weakref callbacks in Python or rather pycurl (it drives a curl instance and curl has to free the memory it allocated)
```

## TODO
- [x] Diagnose memory leaks;
- [ ] Fix em?
