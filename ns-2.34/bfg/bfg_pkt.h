#ifndef __bfg_pkt_h__
#define __bfg_pkt_h__

#include <packet.h>
#include "bloomfilter.h"

/*BFG = Bloom Filter Gradient*/

#define HDR_BFG(p) hdr_bfg::access(p)


/*Tipos de paquete en el protocolo*/
#define  PAQUETE_FBLOOM       0x01   //Aqui se difunden los BloomFilters
#define  PAQUETE_SUV          0x02   //Indica un mensaje que contiene un arreglo de PacketIdentifier con los paquetes para los que es bueno el nodo receptor
#define  PAQUETE_REQ          0x03   //Contiene un arreglo de PacketIdentifier con los paquetes que está dispuesto a aceptar
#define  PAQUETE_DATOS        0x04   //Se responde un HELLO_PACKET con un DATA_PACKET conteniendo los paquetes para los que sirve


/*     VARIABLES DE LOS FILTROS BLOOM      */
#define  BF_HASH_FUNCTIONS        4  //k El numero de funciones hash a usar para las operaciones del filtro (k)
#define  BF_BUCKETS_IN_FILTER    64  //c La cantidad de "buckets" en el filtro, equivalente al num. de bits (m)
#define  BF_MAX_COUNT            32  //m El valor maximo que puede tomar un "bucket" (c)
#define  BF_SIZE                 48  //  El tamaño en bytes del array que representa al filtro bloom contador
                                        //Se calcula como ceil( (m*B) / 8)
                                        //Donde B=floor(log2(c))+1
                                        //Es igual a CountingFilter::bytes_needed(BF_BUCKETS_IN_FILTER, BF_MAX_COUNT)


#define PACKET_ID_SIZE     18
struct PacketIdentifier
{
    nsaddr_t 	src_;       //4 bytes
    nsaddr_t 	dst_;       //4 bytes
    u_int       size_;      //4 bytes
    u_int16_t   src_port_;  //2 bytes
    u_int16_t   dst_port_;  //2 bytes
    u_int16_t   seq_num_;   //2 bytes
};

inline bool operator<(const PacketIdentifier& left, const PacketIdentifier& right)
{
    if(left.src_ != right.src_){
        return left.src_ < right.src_;
    }else if(left.dst_ != right.dst_){
        return left.dst_ < right.dst_;
    }else if(left.dst_port_ != right.dst_port_){
        return left.dst_port_ < right.dst_port_;
    }else if(left.src_port_ != right.src_port_){
        return left.src_port_ < right.src_port_;
    }else if(left.seq_num_ != right.seq_num_){
        return left.seq_num_ < right.seq_num_;
    }else if(left.size_ != right.size_){
        return left.size_ < right.size_;
    }else {
        //Se concluye que left y right son el mismo identificador de paquete
        return false;
    }
}


/*     TAMAÑOS DE LAS ESTRUCTURAS   */
#define  PACKETS_IN_SUV     20
#define  BFG_HDR_LEN 	    12 + (PACKET_ID_SIZE*PACKETS_IN_SUV)   //bytes
#define  BFG_BFHDR_LEN      12 + BF_SIZE

#define  PROBABILIDAD_DEGRADACION       0.5
#define  FORWARD_THRESHOLD              0.1
#define  PERIODIC_DEGRADATION_INTERVAL  5.0



struct hdr_bfg{
	nsaddr_t     					  src_;
	nsaddr_t     					  dst_;
	u_int16_t  				  		  seq_num_;    //Numero de secuencia, para diferenciar un paquete de otro
    u_int8_t     					  type_;       //Tipo de paquete
    u_int8_t                          suv_qty_;    //Cantidad de elementos que se envian en el SUV

    union{
        byte                          bloom_filter_[BF_SIZE];
        PacketIdentifier              summary_vector_[PACKETS_IN_SUV];
    };


    inline nsaddr_t&            src()               { return src_;           }
    inline nsaddr_t&            dst()               { return dst_;           }
    inline u_int16_t&           seq_num()           { return seq_num_;       }
    inline u_int8_t&            type()              { return type_;          }
    inline u_int8_t&            suv_qty()           { return suv_qty_;       }
    inline byte*                bloom_filter()      { return bloom_filter_;  }
    inline PacketIdentifier*    summary_vector()    { return summary_vector_;}

	static int offset_;
	inline static int& offset() { return offset_; }
	inline static hdr_bfg* access(const Packet* p){
		return (hdr_bfg*) p->access(offset_);
	}
};
#endif 
