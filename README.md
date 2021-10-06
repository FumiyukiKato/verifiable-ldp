# Preventing Manipulation Attack in Local Differential Privacy using Verifiable Randomization Mechanism

https://arxiv.org/abs/2104.06569
(DBSec '21)

Local differential privacy (LDP) has been received increasing attention as a formal privacy definition without a trusted server. In a typical LDP protocol, the clients perturb their data locally with a randomized mechanism before sending it to the server for analysis. Many studies in the literature of LDP implicitly assume that the clients honestly follow the protocol; however, two recent studies show that LDP is generally vulnerable under malicious clients. Cao et al. (USENIX Security ’21) and Cheu et al. (IEEE S&P ’21) demonstrated that the malicious clients can effectively skew the analysis (such as frequency estimation) by sending fake data to the server, which is called data poisoning attack or manipulation attack against LDP. In this paper, we propose secure and efficient verifiable LDP protocols to prevent manipulation attacks. Specifically, we leverage Cryptographic Randomized Response Technique (CRRT) as a building block to convert existing LDP mechanisms into a verifiable version. In this way, the server can verify the completeness of executing an agreed randomization mechanism on the client side without sacrificing local privacy. Our proposed method can completely protect the LDP protocol from output manipulation attacks, and significantly mitigates the unexpected damage from malicious clients with acceptable computational overhead.



### dependencies
Python version is 3.9.1.  
When using pyenv
```
$ pyenv virtualenv 3.9.1 vldp
$ (vldp) pip install -r requirements.txt
```

### example
- wake up server
```bash
$ python server.py --mech krr --cate_num 10 --width 100 --epsilon 3.0 --port 50006 --address 127.0.0.1 
```
- request from client
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

### reproduce all experiment
```
$ script/eval.sh 50006 127.0.0.1 32 1.0 10
```
