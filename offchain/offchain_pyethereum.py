#!/usr/bin/env python

"""
INSTALL:

sudo npm install -g solc

sudo add-apt-repository ppa:ethereum/ethereum
sudo add-apt-repository ppa:ethereum/ethereum-dev
sudo apt-get update
sudo apt-get install solc


sudo ln -s /usr/bin/nodejs /usr/bin/node

pip install ethereum
pip install ethereum-serpent
pip install py-solc
"""

"""
event foo(x:string:indexed, y:bytes:indexed, z:str:indexed)
def moo():
    log(type=foo, text("bob"), text("cow"), text("dog"))
"""


def doit():
    from ethereum import tester as t
    import textwrap
    
    st = t.state()

    code = \
    """
    pragma solidity ^0.4.7;
    contract VoteLogging {
        event LogVote(address voter, uint item_id, uint vote);
        
        function doVote(uint item_id, uint vote) {
            LogVote(msg.sender, item_id, vote);
        }
    }"""

    code = textwrap.dedent(code)
    
    ccont = st.abi_contract(code,
                            language = 'solidity',
                            sender = t.k0,
                            )
    out = []

    st.block.log_listeners.append(lambda x: out.append(ccont._translator.listen(x)))

    vv = {'item_id':2345, 'vote':0}

    print ('PUT', vv)
    
    #ccont.doVote(*vv) ## BROKEN!!?
    ccont.doVote(2345, 0)

    print ('GOT', out)

    assert len(out) == 1
    
    #assert o == [{"_event_type": 'LogVote', "vote": 1}]

if __name__ == '__main__':
    doit()
