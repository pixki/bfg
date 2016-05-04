#ifndef BLOOMFILTER_H
#define BLOOMFILTER_H

#include <iostream>
#include <string>
#include <stdio.h>
#include <cstdlib>
#include <sys/types.h>
#include <time.h>
#include <vector>
#include <cmath>
#include <assert.h>
#include <cstring>
#include <algorithm>
#include <sstream>


using namespace std;


typedef u_int8_t byte;

///Constantes usadas en la hash FNV (http://isthe.com/chongo/tech/comp/fnv/)
#define FNV_prime_32     16777619
#define FNV_init         ((u_int32_t)0x811c9dc5)

#define SEED  2340


class CountingFilter {
public:
    CountingFilter(u_int32_t m, u_int32_t k, u_int32_t maxCount);



    ~CountingFilter();
    CountingFilter   (const CountingFilter& that); //Copy-constructor
    CountingFilter&  operator =(CountingFilter that);
    CountingFilter&  operator +(const CountingFilter& other);
    CountingFilter&  operator +=(const CountingFilter& other);

    void             degrada(double tau);
    friend void swap(CountingFilter& first, CountingFilter& second){
        using std::swap;

        //Comenzamos a intercambiar los datos de primero y segundo
        swap(first.buckets_, second.buckets_);
        swap(first.c_filter, second.c_filter);
        swap(first.elements, second.elements);
        swap(first.hash_functions, second.hash_functions);
        swap(first.maxCount, second.maxCount);

    }




    /**
     Función para probar si existe el objeto en el filtro, observese que, de regresar
     un valor true se debe de interpretar como tal vez esté contenido dentro del filtro.

     @param t El objeto con el que se probará su membresía en el metro.
     */
    template<class T> inline bool test(const T& t) {
        bool retVal = true;
        for (u_int32_t i = 0; i < this->hash_functions; i++) {
            u_int32_t Gi, f1, f2;
            //Calcula el hash Gi = ( h1(key) + i*h2(key) )mod m'
            f1 = FNV32((unsigned char*) &t, sizeof(t));
            f2 = Murmur2((unsigned char*) &t, sizeof(t), CountingFilter::randomKey[i]);
            Gi = (f1 + i * f2) % this->buckets_;
            printf("-tst- Hashes (%d): [%u],[%u]; Gi=%u\n", i, f1, f2, Gi);
            //Gi es el bit que se necesita "prender",  0 <= Gi <= this->size_in_bits
            retVal = (retVal && testElement(Gi));
        }
        return retVal;
    }

    /**
     * Esta función imprime solamente los indices que corresponden al elemento  en
     * este filtro. No tiene efecto alguno en el contenido del filtro
     *
     * @param t El objeto a probar.
     */
    template<typename T> inline void print_hash_values_for(const T &t) {
        ostringstream s1;
        s1 << "H(" << t << ")=[";
        for (u_int32_t i = 0; i < this->hash_functions; ++i) {
            u_int32_t Gi, f1, f2;
            //Calcula el hash Gi = ( h1(key) + i*h2(key) )mod m'
            f1 = FNV32((unsigned char*) &t, sizeof(t));
            f2 = Murmur2((unsigned char*) &t, sizeof(t), CountingFilter::randomKey[i]);
            Gi = (f1 + i * f2) % this->buckets_;

            //printf("\t[c] Gi= (%d + %d * %d) mod %d  = %d //K[%d]=%d\n", f1, i,f2, this->buckets(), Gi, i, CountingFilter::randomKey[i]);
            s1 << Gi;
            if (i != this->hash_functions - 1) {
                s1 << ", ";
            }

        }
        s1 << "]\n";
        cout << s1.str();
    }

    /**
     * Esta función imprime solamente los indices que corresponden al elemento  en
     * este filtro. No tiene efecto alguno en el contenido del filtro
     *
     * @param t El objeto a probar.
     */
    template<typename T> inline std::vector<u_int32_t> hash_values_for(const T &t) {
        std::vector<u_int32_t> valores;

        for (u_int32_t i = 0; i < this->hash_functions; ++i) {
            u_int32_t Gi, f1, f2;
            //Calcula el hash Gi = ( h1(key) + i*h2(key) )mod m'
            f1 = FNV32((unsigned char*) &t, sizeof(t));
            f2 = Murmur2((unsigned char*) &t, sizeof(t), CountingFilter::randomKey[i]);

            Gi = (f1 + i * f2) % this->buckets_;
            valores.push_back(Gi);

        }
        return valores;
    }

    /**
     Función para agregar un elemento al filtro ya construido.

     @param t El objeto a agregar al filtro
     */
    template<typename T> inline void add(const T& t) {
        for (u_int32_t i = 0; i < this->hash_functions; ++i) {
            u_int32_t Gi, f1, f2;
            //Calcula el hash Gi = ( h1(key) + i*h2(key) )mod m'
            f1 = FNV32((unsigned char*) &t, sizeof(t));
            f2 = Murmur2((unsigned char*) &t, sizeof(t), CountingFilter::randomKey[i]);

            Gi = (f1 + i * f2) % this->buckets_;
            //printf("\t[a] Gi= (%d + %d * %d) mod %d  = %d //K[%d]=%d\n", f1, i,f2, this->buckets(), Gi, i, CountingFilter::randomKey[i]);
            //Gi es el bit que se necesita "prender",  0 <= Gi <= this->size_in_bits
            this->c_filter[Gi] = this->maxCount;
        }
        this->elements++;        
    }



    byte*                   serialize();
    static CountingFilter*  deserialize(byte* data, size_t bytes, u_int32_t m, u_int32_t k, u_int32_t c);
    static size_t           bytes_needed(u_int32_t m, u_int32_t c);
    static void             randomkeys_with_seed(u_int32_t seed, u_int32_t k);

    u_int32_t   get_random_key_at(const u_int32_t index) const;
    u_int32_t   get_counter_at(const u_int32_t index)    const; //Regresa el valor del contador (o bucket) especificado por index
    void        set_counter_at(const u_int32_t index, const u_int32_t value);
    void        decrement_bucket(u_int index);
    void        print()     const;
    std::string to_string() const;
    double      saturation() const;


    inline u_int32_t max_count()           const { return this->maxCount;	    }
    inline u_int32_t buckets()             const { return this->buckets_;	    }
    inline u_int32_t hash_functions_used() const { return this->hash_functions; }
    inline u_int32_t size()                const { return this->elements;   	}



    //Todos los filtros Bloom deben de compartir las mismas llaves para que las representaciones sean iguales
    static u_int32_t *randomKey;        //Se crea una "llave" aleatoria para las hashes que requieren de un numero aleatorio (Murmur, HashMix)
    static bool      keys_initialized;  //Indica si alguna instancia ya inicializó las llaves.

protected:

    u_int32_t hash_functions;  	//La cantidad de funciones hash que hay (k)
    u_int32_t *c_filter; //Implementación del arreglo de contadores que representa el filtro
    u_int32_t maxCount; //Número máximo hasta el cual un "bucket" en el filtro puede almacenar
    u_int32_t buckets_;    		//El tamaño en bits del bufer (m)
    u_int32_t elements;        	//Cantidad de elementos almacenados

    void markElement(u_int32_t element);
    bool testElement(u_int32_t element);

    /**
     Calcula el hash FNV (Fowler-Noll-Vo) de un objeto, la hash que calcula es de 32 bits.
     @param p El apuntador al primer byte del objeto del cual se calculará su hash.
     @param bytes Tamaño en bytes del objeto.
     */
    template<class T> inline u_int32_t FNV32(const T *key, size_t bytes) {
        u_int32_t hash = FNV_init;

        const T *end = key + bytes;
        for (const T *chunk = key; chunk < end; ++chunk) {
            hash ^= (u_int32_t) *chunk;    //Hacemos un XOR con el byte actual

            /*Esta expresión alcanza mejores resultados en velocidad si se compila con GCC y la bandera -O3
             de otra manera se utiliza la multiplicación por el número FNV_prime_32. }
             http://www.isthe.com/chongo/tech/comp/fnv/index.html#gcc-O3
             hash *= FNV_prime_32
             */
            hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8)
                    + (hash << 24);
        }
        return hash;
    }

    /**
     Calcula la función hash "Mix" de R. Jenkins de 96bits. Se implementa la funcionalidad del "mix",
     hay pocas referencias a que hacer con datos de mas de 4 bytes.
     http://www.concentric.net/~Ttwang/tech/inthash.htm
     @param key Apuntador hacia los datos a ser hasheados.
     @param bytes Tamaño en bytes de los datos
     */
    template<class T> inline u_int32_t HashMix(const T *key, size_t bytes,
            u_int32_t randomKey) {
        //Tomamos 3 bloques de 4 bytes (32 bits * 3 = 96bits) para mezclar
        u_int32_t a, b, c;
        u_int32_t left = bytes;
        u_int32_t hash;

        const T *chunk = key;
        a = randomKey;
        b = a >> 16;
        while (left > 4) {
            c = *chunk;

            a = a - b;
            a = a - c;
            a = a ^ (c >> 13);
            b = b - c;
            b = b - a;
            b = b ^ (a << 8);
            c = c - a;
            c = c - b;
            c = c ^ (b >> 13);
            a = a - b;
            a = a - c;
            a = a ^ (c >> 12);
            b = b - c;
            b = b - a;
            b = b ^ (a << 16);
            c = c - a;
            c = c - b;
            c = c ^ (b >> 5);
            a = a - b;
            a = a - c;
            a = a ^ (c >> 3);
            b = b - c;
            b = b - a;
            b = b ^ (a << 10);
            c = c - a;
            c = c - b;
            c = c ^ (b >> 15); //El valor del hash para este bloque se queda en c

            //No se especifica como acumular el hash, asi que opté por el XOR
            hash ^= c;
            chunk += 4;
            left -= 4;
        }
        //Hasheamos los 3 o menos bytes que quedan, el procedimiento se toma en base al de la funcion hash de murmur
        if (left > 0) {
            switch (left) {
            case 3:
                hash ^= *(chunk + 2) << 16;
                /* no break */
            case 2:
                hash ^= *(chunk + 1) << 8;
                /* no break */
            case 1:
                hash ^= *chunk;
            }
        }
        return hash;
    }

    /**
     Calcula el valor de hash "Murmur" para el objeto referenciado por key
     https://sites.google.com/site/murmurhash/

     @param(key) El apuntador al objeto del cual se calculará su hash
     @param(bytes) El tamaño en bytes del objeto
     */
    template<class T> inline u_int32_t Murmur2(const T *key, size_t bytes,
            u_int32_t randKey) {
        //Constantes para mezclar, propuestas originalmente en el algoritmo
        const unsigned int m = 0x5bd1e995;
        const int r = 24;

        //El hash se inicializa en un valor aleatorio, la semilla usada está en el constructor de la clase
        u_int32_t hash = randKey;

        const T *end = key + bytes;
        const T *chunk = key;

        while ((end - chunk) >= 4) { //La mezcla se hace en bloques de 4 bytes.
            //printf("chunk: %02X (%c)\n", *chunk, *chunk);
            u_int32_t block = *(u_int32_t *) chunk;
            //printf("Bloque: %04X\n", block);
            block *= m;
            block ^= (block >> r);
            block *= m;

            hash *= m;
            hash ^= block;

            chunk += 4;
        }

        switch (bytes % 4) //Si quedaron bytes sin hashear, aqui se tratan
        {
        case 0:
            break; //Nada que hacer, todos los bytes se hashearon
        case 3:
            hash ^= *(chunk + 2) << 16;
            /* no break */
        case 2:
            hash ^= *(chunk + 1) << 8;
            /* no break */
        case 1:
            hash ^= *chunk;
            hash *= m;
        }
        hash ^= hash >> 13;
        hash *= m;
        hash ^= hash >> 15;
        return hash;
    }
};



#endif // BLOOMFILTER_H
