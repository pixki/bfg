#ifndef __epidemic_pkt_h__
#define __epidemic_pkt_h__

#include <packet.h>

#define HDR_EPI(p) hdr_epi::access(p)


/*Tipos de paquete en epidemic*/
#define  SUV_PACKET      0x01
#define  REQ_PACKET      0x02
#define  DAT_PACKET      0x04

#define  EPI_HDR_LEN 	     13  + (sizeof(EpiPacketIdentifier)*PACKETS_PER_SUV)   //bytes
#define  PACKETS_PER_SUV     20

struct EpiPacketIdentifier
{
	nsaddr_t 	src_;       //4 bytes
	nsaddr_t 	dst_;       //4 bytes
	u_int       size_;      //4 bytes
	u_int16_t   src_port_;  //2 bytes
	u_int16_t   dst_port_;  //2 bytes
	u_int16_t   seq_num_;   //2 bytes
};

inline bool operator<(const EpiPacketIdentifier& left, const EpiPacketIdentifier& right)
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



struct hdr_epi{
	nsaddr_t     		src_;
	nsaddr_t     		dst_;
	u_int16_t    		id_qty_;
	u_int16_t    		seq_num_;    //Numero de secuencia, para diferenciar un paquete de otro
	u_int8_t     		type_;       //Tipo de paquete para epidemic, puede ser QRY, UPD, SV
	EpiPacketIdentifier	id_[PACKETS_PER_SUV]; //Arreglo con los identificadores de paquete que se enviaran como resumen

	inline nsaddr_t&    src()        { return src_;         }
	inline nsaddr_t&    dst()        { return dst_;         }
	inline u_int16_t&   id_qty()     { return id_qty_;      }
	inline u_int16_t&   seq_num()    { return seq_num_;     }
	inline u_int8_t&    type()       { return type_;        }
	inline EpiPacketIdentifier* id() { return id_;          }

	static int offset_;
	inline static int& offset() { return offset_; }
	inline static hdr_epi* access(const Packet* p){
		return (hdr_epi*) p->access(offset_);
	}
};
#endif 
