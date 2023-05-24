# Elf ET_REL files converter
Program which converts `ET_REL` x86_64 files to `ET_REL` AArch64 files, written for _Advanced topics in operating systems_ University Course.
Below you can find a content of _README.md_ that was submitted as a part of the solution.

## Zadanie 1: Konwerter plików binarnych
###### Mateusz Nowakowski, ZSO 2022/23
### Opis rozwiązania
Rozwiązanie w języku **C++**
#### Użyte biblioteki
* [elfio](https://elfio.sourceforge.net/) - do parsowania i tworzenia plików ELF
* [Capstone](https://www.capstone-engine.org/) - do deasemblacji
* [Keystone](https://www.keystone-engine.org/) - do asemblacji
#### Opis działania

Nie wydaje mi się, żeby w kodzie działo się coś niestandardowego, jednak zostawiam krótki opis działania konwertera.

W rozwiązanie składa się z trzech faz
1. Parsowanie pliku elf 
   1. Dla każdej sekcji która powinna znaleźć się w wynikowym pliku - agregowanie symboli oraz relokacji jej dotyczących w jedno miejsce
2. Następnie dla każdej sekcji
   1. Posortuj relokacje jej dotyczące (po offsetcie) 
   2. Posortuj symbole jej dotyczące (po offsetcie)
   3. Przetwarzaj dane sekcji od adresu `0` w górę - dopóki się nie skończy
      1. Weź maksymalny spójny fragment sekcji niezawierający w sobie funkcji - popraw relokacje oraz symbole w nim występujące - wysrarczy poprawić offsety oraz typy relokacji (zakłądamy że będziemy natrafiać w takim fragmencie jedynie na symbole typu `STT_NOTYPE` oraz `STT_OBJECT`) oraz przepisz jej dane do wynikowego ELFa (chyba że sekcja ma typ `SHT_NOBITS` :) )
      2. Weź funkcję, popraw ją zgodnie z wytycznymi z polecenia, zapisz w jej dane w wynikowej sekcji (ustaw dla nowych relokacji odpowiedni adres w nowej sekcji, nie poprawiaj indeksu symbolu, zrobisz to później)
3. Kiedy przetworzysz każdą sekcję, stwórz sekcję symboli. Zapisz tam każdy przetworzony symbol. Gdy to zrobisz, popraw indeksy symboli we wszystkich relokacjach, tak by dotyczyły symboli w nowym pliku Elf.
4. Stwórz ostateczny plik Elf.

#### Uwagi
1. Zakładam, że nie ma jumpów do "środka" prologu lub epilogu. Skoczyć można jedynie na początek tych fragmentów.
2. Zakładam, że jest co najwyżej jedna sekcja relokacji dla danej sekcji.
3. Reszta przyjętych założeń jest widoczna w warunkach asercji, które są zostawione w kodzie.
4. Domyślnie warningi oraz debug logi są włączone. By je wyłączyć należy ustawić makro `M_DEBUG` w pliku _src.Utils.h_ na `false`.

### Uruchamianie
Należy pobrać odpowiednie biblioteki, <em>Capstone</em>, <em>Keystone</em> oraz _elfio_

#### Instalacja Capstone
```bash
sudo apt-get update
sudo apt-get install libcapstone-dev
```
##### Instalacja Keystone
```bash
git clone https://github.com/keystone-engine/keystone/
cd keystone
mkdir build
cd build
../make-share.sh
sudo make install
sudo sh -c 'echo "/usr/local/lib" >> /etc/ld.so.conf'
sudo ldconfig
```
#### Dalsze kroki
Następnie w katalogu w którym chcemy mieć rozwiązanie, rozpakowujemy je i dodajemy source code biblioteki elfio
````bash
tar xf mn418323.tar
wget https://github.com/serge1/ELFIO/releases/download/Release_3.11/elfio-3.11.tar.gz
tar xf elfio-3.11.tar.gz
````
#### Budowanie
Standardowe, z użyciem programu `cmake`
```bash
mkdir build
cd build
cmake ..
make
```
Jeżeli udało się zainstalować biblioteki Keystone i Capstone, tak że znalezione zostaną przez pkg-config wszystko powinno się zbudować

