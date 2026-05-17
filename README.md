# Keysight Student Challenge 2026

## Arhitectura

(RX): Pachetele intra pe Portul 0 si sunt puse intr-o coada initiala (task_ring).

Clasificare: Pachetele sunt analizate in paralel si impartite in 8 cozi diferite (profile_queue[0] pana la 7).

Procesare (Workeri): Pachetele din cele 8 cozi sufera modificari (drop sau duplicare).

(TX): Pachetele sunt adunate in tx_ring si trimise afara pe Portul 1.

## Detalii Clasificare

Pentru a imparti traficul in 8 am folosit o logica de bitwise. Fiecare pachet porneste cu un dst_id = 0. Verificam 3 conditii pentru traficul IPv4/TCP.

Bitul 2 (Adauga 4 la ID): Daca adresa IP sursa incepe cu 30 (ex: 30.x.x.x).

Bitul 1 (Adauga 2 la ID): Daca portul destinatie TCP este mai mic decat valoarea mediana 35730.

Bitul 0 (Adauga 1 la ID): Daca pachetul are SYN activat

## Logica de Procesare

Duplicare: Orice pachet care a ajuns intr-o coada cu ID impar este clonat

Drop Rate (Pierdere de pachete): Rata de drop creste in functie de numarul cozii, calculata ca ID coada * 2

## Detalii paralelizare

1. Receptia (LCORE_RX - Core 0)
- Avem un core dedicat citirii pachetelor de pe nic si pentru a le pune in task_ring.

2. Clasificarea (4 threads)

- Am creat 4 thread-uri care se bat pentru a citi din task_ring si sa aplice logica de clasificare,
punandu-le in profile_queue corespunzator.

3. Workeri ( 2 core-uri separate)
- Worker 1 (Core 1): se ocupa de primele 4 clase
- Worker 2 (Core 2): se ocupa de ultimele 4 clase

Ambii workeri se ocupa de logica de duplicare/drop_rate si de a trimite pachetele
catre coada finala, daca acestea nu au pachete apelam functia rt_pause care incetineste cpu-ul
pentru a nu face busy wait.

4. Transmisia (LCORE_TX - Core 3)
- Un core este dedicat pentru a citi pachetele din coada finala si sa le trimita pe port-ul 1.
