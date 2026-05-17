Tabirca Nicolae-Eduard  
Popa Marius

###

Am implementat emulatorul folosind mai multe thread-uri pentru a putea procesa pachetele in paralel. Exista un thread dedicat pentru RX, care citeste pachetele din interfata de intrare si le pune intr-un ring buffer comun (input_ring), si un thread dedicat pentru TX, care preia pachetele procesate din cozile de profil si le transmite mai departe. 
Intre aceste doua thread-uri am folosit minim 2 worker threads care proceseaza pachetele in paralel: clasifica pachetele dupa pattern-uri, aplica regulile de drop, duplicate sau delay si apoi le trimit in coada corespunzatoare.
Comunicarea dintre thread-uri se face prin rte_ring, o structura lock-free oferita de DPDK, care permite transferul rapid de pachete fara mutex-uri globale. Numarul de workeri poate fi crescut la orice valoare, insa performanta depinde direct de numarul de core-uri disponibile pe procesor, deoarece fiecare worker ruleaza pe un lcore separat.

Pentru rulare am modificat dockerfile si scriptul de rulare, astfel incat sa am `4 core-uri`.   
Am rulat in container: `cd /workspace/netem && meson compile -C build && ./run.sh`