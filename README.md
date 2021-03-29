# verifiable-ldp

Python 3.9.1

### example
```bash
$ python server.py --mech krr --cate_num 10 --width 100 --epsilon 3.0 --port 50006 --address 127.0.0.1 
```
```bash
$ python client.py --mech krr --cate_num 10 --width 100 --epsilon 3.0 --port 50006 --address 127.0.0.1 --sensitive_value 2
```

### usage
`python server.py`
```
usage: server.py [-h] [--mech MECH] [--cate_num CATE_NUM] [--width WIDTH] [--epsilon EPSILON] [--port PORT] [--address ADDRESS] [--g G]

Execute output-secure LDP protocols in Server role.

optional arguments:
  -h, --help           show this help message and exit
  --mech MECH          used mechanism [krr, oue, olh] (default: krr)
  --cate_num CATE_NUM  number of cateogories (default: 5)
  --width WIDTH        distribution accuracy parameter (default: 100)
  --epsilon EPSILON    privacy budget used in LDP protocol (default: 1.0)
  --port PORT          bind port (default: 50007)
  --address ADDRESS    bind address (default: 127.0.0.1)
  --g G                output space size (g < cate_num) when mech=olh (default: 5)
  ```

`python client.py`
```
usage: client.py [-h] [--mech MECH] [--cate_num CATE_NUM] [--width WIDTH] [--epsilon EPSILON] [--port PORT] [--address ADDRESS] [--sensitive_value SENSITIVE_VALUE] [--g G]

Execute output-secure LDP protocols in Server role.

optional arguments:
  -h, --help            show this help message and exit
  --mech MECH           used mechanism [krr, oue, olh] (default: krr)
  --cate_num CATE_NUM   number of cateogories (default: 5)
  --width WIDTH         distribution accuracy parameter (default: 100)
  --epsilon EPSILON     privacy budget used in LDP protocol (default: 1.0)
  --port PORT           bind port (default: 50007)
  --address ADDRESS     bind address (default: 127.0.0.1)
  --sensitive_value SENSITIVE_VALUE sensitive value (default: 0)
  --g G                 output space size (g < cate_num) when mech=olh (default: 5)
  ```