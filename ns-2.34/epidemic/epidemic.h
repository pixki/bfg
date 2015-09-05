#ifndef  __epidemic_h__
#define  __epidemic_h__

#include "epidemic_pkt.h"
#include <agent.h>
#include <packet.h>
#include <trace.h>
#include <priqueue.h>
#include <random.h>
#include <classifier-port.h>

#include <cstdlib>
#include <iostream>
#include <iomanip>
#include <list>

//Para la cola de prioridades (ademas de cstdlib e iostream)
#include <queue>
#include <iterator>
#include <algorithm>



using namespace std;

#define  CURRENT_TIME          Scheduler::instance().clock()
#define  JITTER                (Random::uniform()*0.5)


#define  HELLO_INTERVAL        1               // 1000 ms
#define  MaxHelloInterval      (1.25 * HELLO_INTERVAL)
#define  MinHelloInterval      (0.75 * HELLO_INTERVAL)




#define  BUFFER_SIZE           2048
#define  MAX_TIME_IN_BUFFER    50.0
#define  MAX_NUMBER_OF_COPIES  15






#define EPI_TRACE(format, ...)   if(logtarget_ != 0) { sprintf(logtarget_->pt_->buffer(), format , __VA_ARGS__); logtarget_->pt_->dump();}else{fprintf(stdout, "%f _%d_ No se definió un archivo de traza, favor de indicarlo en el script", CURRENT_TIME, local_address());	}



class Epidemic;


class EpidemicHelloTimer : public Handler{
public:
	EpidemicHelloTimer(Epidemic* a) { agent_ = a; }
	void handle(Event* );
    void cancel();
private:
	Epidemic*      agent_;
	Event          intr_;    
};




/*Cada entrada representa a un paquete unico*/
struct BufferEntry{
	nsaddr_t 	src_id_;      //4 bytes
	nsaddr_t 	dst_id_;      //4 bytes
	u_int       size_;        //4 bytes
	u_int16_t   src_port_;    //2 bytes
	u_int16_t   dst_port_;    //2 bytes
	u_int16_t   seq_num_;     //2 bytes
	double      inserted_at_; //
	u_int       copies_;      //4 bytes
};

/*Cada entrada en el cache representa el estado de un flujo*/
struct CacheEntry{
	nsaddr_t 	src_;       //4 bytes
	nsaddr_t 	dst_;       //4 bytes
	u_int16_t   seq_num_;   //2 bytes	
};



/*
 * Clase de comparación entre dos entradas en el buffer. Decide
 * cual de las dos es de mayor prioridad
 * */
class CompareBufferEntry{
public:
	/*Regresa cierto si b1 es de mayor prioridad que b2*/
	bool operator()(BufferEntry& b1, BufferEntry& b2){
        if(b1.copies_ > b2.copies_ ) return true; //mayor numero de copias representa menor prioridad
        if(b1.copies_==b2.copies_ && b1.inserted_at_ > b2.inserted_at_) return true;// el mas viejo primero(insertado mas temprano)
		return false;
	}
};



class OrderBufferByOldest{
    public:
    bool operator()(BufferEntry &b1, BufferEntry& b2){
        if(b1.inserted_at_ > b2.inserted_at_) return true; //b1 precede a b2 en la prioridad
        return false; //Para todos los demás casos
    }
};

/**
 * Clase que representa una cola de prioridades, hereda directamente de
 * la clase Vector y no de priority_queue para permitir el acceso al
 * contenedor de datos subyaciente sin tener que eliminar registros
 * del mismo.
 * Se inicializa de la siguiente forma:
 *     BufferPQ<T, Compare> var;
 * Donde:
 *    T es el tipo de datos que se almacenará en la estructura
 *    Compare es una clase que sobrecarga el operador () mediante el cual establece las prioridades entre dos objetos
 *
 * */
template<class T, class Compare> class BufferPQ : public vector<T> {
	Compare comp;
	bool sorted;

	/**
	 * Con esta funcion nos aseguramos que si la estructura subyaciente (vector)
	 * está ordenado, entonces lo convertimos a una estructura heap, se llama
	 * justo antes de realizar operaciones de heap a la estructura.
	 * */
	void assureHeap() {
		if(sorted) {
			// Turn it back into a heap:
			make_heap(this->begin(),this->end(), comp);
			sorted = false;
		}
	}
public:
	BufferPQ(Compare cmp = Compare()) : comp(cmp) {
        make_heap(this->begin(),this->end(), comp);
		sorted = false;
	}

	const T& top() {
		assureHeap();
		return this->front();
	}

	void push(const T& x) {
		assureHeap();
		this->push_back(x); // Put it at the end
		push_heap(this->begin(),this->end(), comp);// Re-adjust the heap
	}

	void pop() {
		assureHeap();
		// Move the top element to the last position:
		pop_heap(this->begin(),this->end(), comp);
		this->pop_back();// Remove that element
	}

	void sort() {
		if(!sorted) {
			sort_heap(this->begin(),this->end(), comp);
			reverse(this->begin(),this->end());
			sorted = true;
		}
    }
};














/*El Agente*/
class Epidemic : public Agent{

	friend class EpidemicHelloTimer;

private:
	nsaddr_t      			 local_addr_;          //Representa la direccion asignada a este nodo
    u_int16_t             	 seq_num_;             //Lleva el numero de secuencia a asignar al siguiente paquete
    bool                    proto_enabled_;
    

    BufferPQ<BufferEntry, CompareBufferEntry> buffer_;
    // list <BufferEntry>       buffer_;              //La lista que contiene los elementos almacenados.
    list <CacheEntry>        cache_;               //Lista que guardará el ultimo paquete recibido, identificado por la 4-tupla (src,dst, src port, dst port)

protected:
	PortClassifier*     	 dmux_;
	Trace*                   logtarget_;
	EpidemicHelloTimer       helloTimer_;
	// A pointer to the network interface queue that sits between the "classifier" and the "link layer"
    PriQueue	             *ifqueue;


	inline nsaddr_t&         local_address() { return local_addr_;  }

	void 					 reset_epidemic_pkt_timer();

	/*
	 * Paquetes de epidemic, el orden en que están declaradas es el orden en que se interactua
	 */
	void					 send_summary_vector();             
    void					 receive_summary_vector(Packet* p);
    void                     send_request_packet(nsaddr_t dest, list<EpiPacketIdentifier> petition);
    void					 receive_packets_request(Packet* p);
    void					 receive_data_packets(Packet* p);


	
	//Relacionadas a la caché
	void                     update_cache(EpiPacketIdentifier p);        //Inserta el descriptor de paquete en el buffer de caché para indicar el ultimo paquete recibido
	bool                     is_cached(EpiPacketIdentifier pi);        //Devuelve el valor logico sobre si pedir o no el paquete en base a la cache
	void                     dump_cache();

	//Relacionados al buffer interno
	void            		 insert_packet(Packet *p);                //Debe de agregar paquetes al buffer (se supone que son desconocidos)
	bool                     exists_in_buffer(BufferEntry p);
	void                     add_identifier_to_buffer(EpiPacketIdentifier p);//Inserta paquetes
	void                     copy_created(EpiPacketIdentifier p);
	bool                     is_in_buffer(EpiPacketIdentifier pi);
	void                     dump_buffer();


    list<EpiPacketIdentifier>   get_packets_to_xmit();                   //regresa la lista de paquetes que
    list<EpiPacketIdentifier>   get_all_packets_in_buffer();             //Regresa todos los paquetes en el buffer


	/* Funciones de ayuda */
	void       				 hexDump(const unsigned char* buffer, int size_in_bytes, const char* msg);
	void                     asciiDump(const unsigned char* buffer, int size_in_bytes, const char* msg);
	list<EpiPacketIdentifier>   get_random_subset(int subset_size);

public:
	Epidemic        		(nsaddr_t);
	int    command  		(int, const char* const*);
	void   recv     		(Packet* , Handler* );
	void   mac_failed       (Packet* p);
};



#endif
