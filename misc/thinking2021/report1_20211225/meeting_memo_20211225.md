## 20211225 meeting memo

### record during meeting

- vul that cannot be exploit by using SLAKE and ELOISE, we need more demos
- RIP hijacking and arb read/write is the ultimate goal of exploitation, but sometimes we have to do it in multi stages
- security conference papers require general work, our work must be able to be applied to general cases. (unlike BlackHat)
- by adding more dimensions to vul model (consider more powerful vul capabilities), more exploitation path may be found
- vul state transformation, second-order bug. (FUZE, Revery, MAZE)
- consider the state of the current vul as a stage and the ultimate goal(e.p. RIP hijacking) as a stage, fuzz from current vul state toward ultimate state
- the idea may be implemented by directed-fuzz (the fuzz can be guided by heuristic knowledge of exploitation, by mark exploitation possibility of each state)



### thinking

- second-order and multi-stage can be a good model
- no matter how the vul state transformed, for most cases the ultimate goal is always RIP hijacking / arb write(read)
- I need to find more vul that can demonstrate SLAKE and ELOISE is insufficient (to prove a lot of vul cannot be exploited by such straight forward methods, to prove we need multi-stage exploitation path)
- I need to figure out a way to guide fuzz by heuristic knowledge of exploitation



### things to do

- search recent kernel vul CVEs and CTF kernel pwn to find more demos
- revisit FUZE, Revery and MAZE



