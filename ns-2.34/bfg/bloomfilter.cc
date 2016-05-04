#include "bloomfilter.h"
#include <cmath>
#include <assert.h>
#include <cstring>
#include <bitset>
#include <sstream>
#include <iomanip>

using namespace std;



u_int32_t* CountingFilter::randomKey        = NULL;
bool       CountingFilter::keys_initialized = false;


CountingFilter::CountingFilter(u_int32_t m, u_int32_t k, u_int32_t maxCount) {

    if(!CountingFilter::keys_initialized){
        srand(SEED);
        this->randomKey = new u_int32_t[k]; //Se inicializan las llaves aleatorias para cada función
        for (u_int32_t i = 0; i < k; i++) {
            this->randomKey[i] = (u_int32_t) rand();
        }
        CountingFilter::keys_initialized = true;
    }


    this->c_filter = new u_int32_t[m];
    this->buckets_ = m;
    this->hash_functions = k;
    this->elements = 0;
    this->maxCount = maxCount;
    memset(this->c_filter, 0, sizeof(u_int32_t) * m);
}

CountingFilter::~CountingFilter() {
    if (this->c_filter != NULL) {
        delete[] this->c_filter;
        this->c_filter = NULL;
    }
    //No se libera la memoria de las randKeys, ya que son estáticas y se necesitan para las demás instancias
    //Como solución se puede implementar una variable estatica de contador de instancias.
}

//Copy-constructor
CountingFilter::CountingFilter(const CountingFilter& that){
    //Crear memoria para las variables dinamicas
    this->c_filter = new u_int32_t[that.buckets()];
    //No se necesita asignar espacio para las llaves de la hash Murmur porque son estáticas

    for(u_int32_t i=0; i<that.buckets(); i++){
        this->c_filter[i] = that.get_counter_at(i);
    }
    this->buckets_ = that.buckets();
    this->elements = that.size();
    this->hash_functions = that.hash_functions_used();
    this->maxCount = that.max_count();
}



void
CountingFilter::randomkeys_with_seed(u_int32_t seed, u_int32_t k)
{
    srand(seed);
    CountingFilter::randomKey = new u_int32_t[k]; //Se inicializan las llaves aleatorias para cada función
    for (u_int32_t i = 0; i < k; i++)
    {
        CountingFilter::randomKey[i] = (u_int32_t) rand();
        printf("\tKey[%d]=%d\n", i, CountingFilter::randomKey[i]);
    }
    CountingFilter::keys_initialized = true;
}



CountingFilter&
CountingFilter::operator=(CountingFilter newVal){
    swap(*this, newVal);
    return *this;
}

CountingFilter&
CountingFilter::operator+(const CountingFilter& other){
    CountingFilter current(*this);
    u_int32_t maxval=0;
    for(u_int32_t i=0; i<other.buckets(); i++){
        maxval = other.get_counter_at(i)>this->get_counter_at(i)? other.get_counter_at(i):current.get_counter_at(i);
        this->set_counter_at(i, maxval);
    }
    return *this;
}


CountingFilter&
CountingFilter::operator +=(const CountingFilter& other){
    CountingFilter current(*this);
    for(u_int32_t i=0; i<other.buckets(); i++){
        u_int32_t temp=current.get_counter_at(i);
        if(other.get_counter_at(i) > current.get_counter_at(i))
            this->set_counter_at(i, other.get_counter_at(i));
        //printf("\t\t %d > %d? ==> %d \n", other.get_counter_at(i), temp, this->get_counter_at(i));
    }
    return *this;
}


void
CountingFilter::degrada(double tau){
    double random_val=0.0;
    srand(SEED);

    //Un filtro vacío con los mismos parametros de cbf
    //CountingFilter out_filter(cbf.buckets(), cbf.hash_functions_used(), cbf.max_count());

    #ifdef DBG_DEGRAD
        cout<<"------------------DEBUG DEGRADACION-----------------------"<<endl;
        cout<<"cbf:";
        cbf.print();
        cout<<"Res:";
        result.print();
        cout<<".........................................................."<<endl;
    #endif

    for(u_int32_t i= 0; i < this->buckets_; i++){
        random_val = (rand() % 100) / 100.0;
        //cout<<"RanVal: "<<random_val <<" ; PrD: " << PROBABILIDAD_DEGRADACION;
        if(random_val <= tau){
            if(this->c_filter[i] > 0){
                //cout<<" => F["<<i<<"]-- ";
                this->c_filter[i]-=1;
                //out_filter.set_counter_at(i, cbf.get_counter_at(i) - 1);
            }
        }
        //cout<<endl;
    }

    #ifdef DBG_DEGRAD
        cout<<"cbf:";
        cbf.print();
        cout<<"Res:";
        result.print();
        cout<<"-----------------/DEBUG DEGRADACION-----------------------"<<endl;
    #endif

}


u_int32_t
CountingFilter::get_random_key_at(u_int32_t index) const{
    if(index<this->hash_functions)
        return CountingFilter::randomKey[index];
    return 0;
}


u_int32_t
CountingFilter::get_counter_at(const u_int32_t index) const{
    if(index < this->buckets_)
        return this->c_filter[index];
    return 0;
}

void
CountingFilter::set_counter_at(const u_int32_t index, const u_int32_t value){
    if(index < this->buckets_ && value <= this->maxCount)
        this->c_filter[index] = value;
}


bool CountingFilter::testElement(u_int32_t element)
{
    return (this->c_filter[element] != 0);
}



void CountingFilter::decrement_bucket(u_int index){
    if(index < this->buckets_ && //Debe de ser un indice valido
       this->c_filter[index] > 0)    //Y el bucket no puede ser negativo
        this->c_filter[index]--;
}

void
CountingFilter::print() const {
    cout<<"Bf="<< to_string() <<endl;
}



std::string
CountingFilter::to_string() const{
    std::string out;
    std::stringstream ss;

    out.reserve(6*this->buckets() + 10);
    //out.append("[");
    for(u_int32_t i=0; i<this->buckets_; i++){
        ss << std::setw(2) << std::setfill('0') << this->c_filter[i];
        out += std::string(ss.str());
        ss.str(std::string());

        if(i!=(this->buckets_-1))
            out += " ";

    }
    //out += "]";
    return out;
}


double
CountingFilter::saturation() const
{
    double sat=0.0;
    for(u_int32_t i =0; i<this->buckets_; i++)
        sat += (get_counter_at(i) + 0.0 );
    sat /= (this->maxCount*1.0*this->buckets_);
    return sat;
}

void
print_int32(u_int32_t in)
{
    bitset<32> bs(in);
    cout<<"Int." << in << ":" << bs<<endl;
}

void
print_byte(byte in)
{
    bitset<8> bs(in);
    cout<<"Byte "<<in<<":"<<bs<<endl;
}




/**
 * @brief serialize Serializa el filtro Bloom a una estructura de bits
 * @return El arreglo de bytes representando el filtro.
 */
byte*
CountingFilter::serialize()
{
    //cout<<"Serializando"<<endl;
    u_int32_t bits_per_counter =  std::floor(std::log(this->maxCount) / std::log(2)) + 1;
    u_int32_t bytes = std::ceil((bits_per_counter * this->buckets_) / 8.0);

    byte* output = new byte[bytes];

    //cout<<"Cada contador (max. "<<this->maxCount<<") se puede representar con " << bits_per_counter << " bits"<<endl;

    u_int32_t byte_offset=0;
    u_int32_t bit_offset=0;
    u_int32_t current_bit=0;
    u_int32_t counter_bit=0;

    byte out=0;

    for(u_int32_t i=0; i<this->buckets_; i++)
    {
        u_int32_t counter = this->c_filter[i];
        u_int32_t bitmask = 0;
        for(u_int32_t l=0; l<bits_per_counter; l++)
            bitmask = ((bitmask) << 1) | 1;

        counter &= bitmask;

        counter_bit=0;

        for(u_int32_t j=0; j<bits_per_counter; j++)
        {
            if((current_bit%8)==0 && current_bit > 0)
            {
                //cout<<"Byte producido: "; print_byte(out); cout<<endl;
                output[byte_offset] = out;
                //Agregar el byte recién terminado al arreglo
                byte_offset++;
                bit_offset=0;
                out=0;
            }

            //Probamos si el bit actual esta encendido
            byte bit_value = ((1<<(counter_bit)) & counter) ? 1:0;
            //Recorremos el bit a la posicion que debe estar en el byte
            bit_value <<= bit_offset;
            //Y lo prendemos si aplica
            out |= bit_value;

            counter_bit++;
            bit_offset++;
            current_bit++;
        }
        if(i==(this->buckets_ - 1))
        {
            //cout<<"Ultimo byte: "; print_byte(out); cout<<endl;
            output[byte_offset] = out;
        }
    }
    return output;
}

CountingFilter*
CountingFilter::deserialize(byte *data, size_t bytes, u_int32_t m, u_int32_t k, u_int32_t c)
{
    //cout<<"Deserializando..."<<endl;

    CountingFilter* obj=NULL;
    size_t bN = bytes_needed(m,c);
    if( bytes != bN)
    {
        cout<<"ERROR: NUMBER OF BYTES MISMATCH FOR SPECIFIED BloomFilter ("<< bytes<< ") vs. "<< bN << " bytes needed."<< endl;
        exit(1);
    }

    obj = new CountingFilter(m,k,c);    
    u_int32_t counter_value=0;
    u_int32_t bits_per_counter = std::floor( std::log(c) / std::log(2) ) + 1;
    u_int32_t bits_consumed=0;
    u_int32_t counter_bit=0;
    u_int32_t current_counter=0;

    for(u_int32_t by = 0; by < bytes; by++)
    {
        for(u_int16_t bit=0; bit<8; bit++)
        {
            byte bit_value=((1<<(bit)) & data[by])? 1:0;
            bit_value <<= counter_bit;
            counter_value |= bit_value;

            counter_bit++;
            bits_consumed++;

            if(((bits_consumed % bits_per_counter)==0) && bits_consumed > 0)
            {
                //cout<<"Counter "<< current_counter <<" = "<<counter_value<<endl;
                obj->set_counter_at(current_counter, counter_value);
                current_counter++;
                counter_value=0;
                counter_bit = 0;

                if(current_counter == m)
                    return obj;
            }

        }
    }
    return NULL;
}


size_t
CountingFilter::bytes_needed(u_int32_t m, u_int32_t c)
{
    u_int32_t bits_per_counter = std::floor( std::log(c) / std::log(2) ) + 1;
    return std::ceil(( bits_per_counter * m) / 8.0);
}
