#ifndef  __bfg_h__
#define  __bfg_h__

#include "bfg_pkt.h"
#include <agent.h>
#include <packet.h>
#include <trace.h>
#include <priqueue.h>
#include <random.h>
#include <classifier-port.h>

#include <cstdlib>
#include <iostream>
#include <list>
#include <map>
#include <set>





using namespace std;

#define  CURRENT_TIME          Scheduler::instance().clock()
#define  JITTER                (Random::uniform()*0.5)


#define  HELLO_INTERVAL        1.0               // 2000 ms
#define  MaxHelloInterval      (1.25 * HELLO_INTERVAL)
#define  MinHelloInterval      (0.75 * HELLO_INTERVAL)


#define  BUFFER_SIZE           1000


/* LAS VARIABLES DE LOS FILTROS BLOOM ESTAN DEFINIDAS EN EL ARCHIVO bfg_pkt.h*/




#define BFG_TRACE(format, ...)   if(logtarget_ != 0) { sprintf(logtarget_->pt_->buffer(), format , __VA_ARGS__); logtarget_->pt_->dump();}else{fprintf(stdout, "%f _%d_ No se definió un archivo de traza, favor de indicarlo en el script", CURRENT_TIME, local_address());	}



class BFGAgent;


class BFGHelloTimer : public Handler{
public:
	BFGHelloTimer(BFGAgent* a) { agent_ = a; }
	void handle(Event* );
    void cancel();
private:
	BFGAgent*      agent_;
	Event          intr_;
};


class BFDegradationTimer : public Handler{
public:
    BFDegradationTimer(BFGAgent* a) { agent_ = a; }
    void handle(Event* );
    void cancel();
private:
    BFGAgent*   agent_;
    Event       intr_;
};


/*El Agente*/
class BFGAgent : public Agent{

	friend class BFGHelloTimer;
    friend class BFDegradationTimer;

private:
	nsaddr_t      			 local_addr_;          //Representa la direccion asignada a este nodo
    u_int16_t             	 seq_num_;             //Lleva el numero de secuencia a asignar al siguiente paquete
    bool                     proto_enabled_;       //El protocolo está habilitado para funcionar? Usado para simular cuando un nodo sale del área de simulacion
    
protected:
	PortClassifier*     	 dmux_;
	Trace*                   logtarget_;
    BFGHelloTimer            helloTimer_;
    BFDegradationTimer       degradationTimer_;
    bool                     prDebug_;

	// A pointer to the network interface queue that sits between the "classifier" and the "link layer"
    PriQueue	             *ifqueue;


	inline nsaddr_t&         local_address() { return local_addr_;  }

	void 					 reset_bfg_pkt_timer();

	/*
	 * Paquetes del protocolo BFG, el orden en que están declaradas es el orden en que se interactua
	 */
	void					 send_bloom_filter();             
    void					 receive_bloom_filter(Packet* p);
    void                     send_data_packet(PacketIdentifier pi, nsaddr_t dest);
    void					 receive_data_packet(Packet* p);
    void                     send_suv(nsaddr_t dest, list<PacketIdentifier> resume);
    void                     receive_suv(Packet* p);
    void                     receive_request(Packet* p);

    /*
     *  Funciones del protocolo
     */    
    double					 pro_calc_prob(const PacketIdentifier &packet, CountingFilter &cbf);
    double                   probabilityTo(nsaddr_t dst) const;
    void                     pro_actualiza_bf(CountingFilter &cbf);
    //void                     pro_guarda_bf(nsaddr_t &addr, CountingFilter &cbf);
    void  					 pro_degradacion_periodica();

    /*
	*  Funciones y objetos relacionados con los filtros Bloom	
    */
    CountingFilter *fb_propio_; 				//contiene únicamente la direccion local_addr_
    CountingFilter *fb_tiempo_;   			//Varia con el tiempo, sobre este filtro se aplicaran las operaciones y se enviará
    //map<nsaddr_t, CountingFilter> N_; 	//Contenedor de todos los filtros Bloom que ha recibido de otros nodos


    //Relacionados al buffer y cache interno
	//El buffer interno es una lista de PacketIdentifier
	list<PacketIdentifier>   buffer_;
    set<PacketIdentifier>    cache_;
    void                     add_to_cache(PacketIdentifier pi);
    bool                     check_packet_cache(PacketIdentifier pi);
    void            		 insert_packet(Packet *p);                    //Debe de agregar paquetes al buffer (se supone que son desconocidos)
	void                     add_identifier_to_buffer(PacketIdentifier p);//Inserta paquetes
	bool                     is_in_buffer(PacketIdentifier pi);
	void                     dump_buffer();
    void                     print_bfrepr();

    /* Funciones de cache de contactos  */
    //map<nsaddr_t, double>    contact_cache_;
    //void                     actualiza_cc(nsaddr_t);


	/* Funciones de ayuda */
    void                     print_bloomfilter(nsaddr_t dst);
	void       				 hexDump(const unsigned char* buffer, int size_in_bytes, const char* msg);
	void                     asciiDump(const unsigned char* buffer, int size_in_bytes, const char* msg);

public:
    BFGAgent                (nsaddr_t);
	int    command  		(int, const char* const*);
	void   recv     		(Packet* , Handler* );
	void   mac_failed       (Packet* p);
};



#endif
