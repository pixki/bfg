#include "bfg.h"
#include <cmu-trace.h>
#include <iostream>
#include <tclcl.h>
#include <cstdio>
#include <cstring>
#include <algorithm> //std::max()
#include <mobilenode.h>

int hdr_bfg::offset_;

static class bfgHeaderClass: public PacketHeaderClass {
public:
	bfgHeaderClass() :
			PacketHeaderClass("PacketHeader/BFG", sizeof(hdr_bfg)) {
		bind_offset(&hdr_bfg::offset_);
	}
} class_rtProtoBFG_hdr;

/*TCL Hook*/
static class BFGClass: public TclClass {

public:
	BFGClass() :
			TclClass("Agent/BFG") {
	}
	TclObject* create(int argc, const char* const * argv) {
		assert(argc == 5);
		return (new BFGAgent((nsaddr_t) Address::instance().str2addr(argv[4])));
	}
} class_rtProtoBFG;

/*----------------------------------------------------------------------------------------------*/
/*Implementacion del timer para maenjar los paquetes hello                                      */
/*----------------------------------------------------------------------------------------------*/
void
BFGHelloTimer::handle(Event* e) {

    if(!agent_->proto_enabled_) return;

	agent_->send_bloom_filter();
	double interval = MinHelloInterval
			+ ((MaxHelloInterval - MinHelloInterval) * Random::uniform());
	assert(interval >= 0);
	//Nos aseguramos que exsta cierto desfase entre los nodos al enviar paquetes de hola
	Scheduler::instance().schedule(this, &intr_, interval);
}

void 
BFGHelloTimer::cancel(){
    Scheduler::instance().cancel(&intr_);
}


void
BFDegradationTimer::handle(Event *e){
    if(!agent_->proto_enabled_) return;

    agent_->pro_degradacion_periodica();
    Scheduler::instance().schedule(this, &intr_, PERIODIC_DEGRADATION_INTERVAL);
}

void
BFDegradationTimer::cancel(){
    Scheduler::instance().cancel(&intr_);
}



static void
bfg_mac_failed_callback(Packet* p, void *arg) {
	((BFGAgent*) arg)->mac_failed(p);
}



void
BFGAgent::mac_failed(Packet* p) {
	struct hdr_cmn* ch = HDR_CMN(p);
    //struct hdr_ip* ih = HDR_IP(p);

	switch (ch->xmit_reason_) {
	case 0: //ARP Max request reached
        //printf("P %f _%d_ BFG --- MAC Error de ARP\n", CURRENT_TIME, local_address());
		break;

		//Los siguientes estand definidos en packet.h
		case XMIT_REASON_RTS://0x01 Too many RTS but no CTS
		printf("P %f _%d_ BFG --- MAC Error de RTS\n", CURRENT_TIME,local_address());
		break;
		case XMIT_REASON_ACK://0x02 No ACK received when transmitting data packet
		printf("P %f _%d_ BFG --- MAC Error de ACK\n", CURRENT_TIME,local_address());
		break;
	}

    /*
	if (ch->ptype() == PT_BFG) {

		struct hdr_bfg* eh = HDR_BFG(p);
		printf("P %f _%d_ BFG --- Error al enviar paquete de BFG en capa 2, [size:%d/src:%d/dst:%d/type:%d]\n", CURRENT_TIME, local_address(), ch->size(), eh->src(), eh->dst(), eh->type());
	} else {
		printf("P %f _%d_ BFG --- Error al enviar paquete en capa 2, [%d/%d/%d/%d]\n", CURRENT_TIME, local_address(), ih->saddr(), ih->daddr(), ch->uid(), ch->size());
	}
    */
	drop(p);
}

/**
 * Constructor del agente de BFG, se le proporciona la dirección de red que usará
 */
BFGAgent::BFGAgent(nsaddr_t id) :
    Agent(PT_BFG), helloTimer_(this) , degradationTimer_(this){

    local_address() = id;

    this->prDebug_=false;

	this->fb_propio_ = new CountingFilter(BF_BUCKETS_IN_FILTER, BF_HASH_FUNCTIONS, BF_MAX_COUNT);
	this->fb_tiempo_ = new CountingFilter(BF_BUCKETS_IN_FILTER, BF_HASH_FUNCTIONS, BF_MAX_COUNT);

    this->proto_enabled_ = false;
    //Cada vez que un nodo introduzca su direccion, debe de llenar cada bucket correspondiente hasta BF_MAX_COUNT
    for(int count=0; count<BF_MAX_COUNT; count++)
        this->fb_propio_->add(id);

    printf("%0.9f _%d_ BFG Iniciando operaciones BLF[m:%d/k:%d/c:%d/bsize:%d/nsize:%lu]\n",
           CURRENT_TIME, local_address(), BF_BUCKETS_IN_FILTER, BF_HASH_FUNCTIONS, BF_MAX_COUNT, BF_SIZE,
           CountingFilter::bytes_needed(BF_BUCKETS_IN_FILTER, BF_MAX_COUNT));
    printf("%0.9f _%d_ BFG     SUVsize=%d\n", CURRENT_TIME, local_address(), PACKETS_IN_SUV);
    printf("%0.9f _%d_ BFG     Ue=%f, Di=%f, Pd=%f \n", CURRENT_TIME, local_address(), FORWARD_THRESHOLD, PERIODIC_DEGRADATION_INTERVAL, PROBABILIDAD_DEGRADACION);
}



/*Especificación de comandos que recibirá desde el simulador el agente.*/
int
BFGAgent::command(int argc, const char* const * argv) {
    printf("%0.9f _%d_ CMD Ejecutando comando %s\n", CURRENT_TIME, local_address(), argv[1]);
	if (argc == 2) {
		if (strcasecmp(argv[1], "start") == 0) {
            //Con el fin de simular entradas y salidas de nodos del area de simulación, se debe invocar el método entersim
			return TCL_OK;
        }else if(strcasecmp(argv[1], "entersim")==0){
            if(!this->proto_enabled_)
            {
                this->proto_enabled_ = true;
                helloTimer_.handle((Event*) 0);
                degradationTimer_.handle((Event*) 0);                
            }
            return TCL_OK;
        }else if(strcasecmp(argv[1], "stop") == 0){
            //Cancelar los timers del protocolo
            printf("%0.9f _%d_ CMD Deteniendo los timers y el funcionamiento del protocolo\n", CURRENT_TIME, local_address());
            helloTimer_.cancel();
            degradationTimer_.cancel();
            this->proto_enabled_ = false;
            return TCL_OK;
        }else if(strcasecmp(argv[1], "bfrepr")== 0){
            print_bfrepr();
            return TCL_OK;
        }else if(strcasecmp(argv[1], "debug") == 0){
            this->prDebug_=true;
            return TCL_OK;        
        }else if(strcasecmp(argv[1], "myid") == 0){
            printf("%0.9f _%d_ MyID: %s \n", CURRENT_TIME, local_address(), this->fb_propio_->to_string().c_str());
            std::vector<u_int32_t> hashes = this->fb_propio_->hash_values_for(local_address());
            printf("%0.9f _%d_ h=(", CURRENT_TIME, local_address());
            for(std::vector<u_int32_t>::iterator it=hashes.begin(); it != hashes.end(); it++)
            {
                printf("%02d,", *it);
            }
            printf(")\n");
            this->fb_propio_->print_hash_values_for(local_address());
            return TCL_OK;        
		}else if(strcasecmp(argv[1], "dump_buffer") == 0){
            dump_buffer();
			return TCL_OK;
        }

	} else if (argc == 3) {
		//Obtiene el dmux para pasar los paquetes a capas superiores del stack
		if (strcmp(argv[1], "port-dmux") == 0) {
			dmux_ = (PortClassifier*) TclObject::lookup(argv[2]);
			if (dmux_ == 0) {
				fprintf(stderr, "%s: %s lookup of %s failed\n", __FILE__,
						argv[1], argv[2]);
				return TCL_ERROR;
			}
			return TCL_OK;

        } else if (strcmp(argv[1], "log-target") == 0
				|| strcmp(argv[1], "tracetarget") == 0) {
			logtarget_ = (Trace*) TclObject::lookup(argv[2]);
			if (logtarget_ == 0)
				return TCL_ERROR;
			return TCL_OK;
        }else if(strcasecmp(argv[1], "dbgprobto") == 0){
            nsaddr_t dst = (nsaddr_t) atoi(argv[2]);
            debug_probability_to(dst);
            return TCL_OK;
        }else if(strcasecmp(argv[1], "seed") == 0){
            u_int32_t seed = (u_int32_t) atoi(argv[2]);
            CountingFilter::randomkeys_with_seed(seed, BF_HASH_FUNCTIONS);
            //Reconstruct the BloomFilters if needed
            return TCL_OK;
        }else if(strcasecmp(argv[1], "bfstatus") == 0){
            nsaddr_t dst = (nsaddr_t) atoi(argv[2]);
            print_bloomfilter(dst);
            return TCL_OK;
		} else if (strcmp(argv[1], "if-queue") == 0) {
			ifqueue = (PriQueue*) TclObject::lookup(argv[2]);

			if (ifqueue == 0)
				return TCL_ERROR;
			return TCL_OK;
		}
	}

	//Ya no hay mas comandos, pasalo a la clase base
	return Agent::command(argc, argv);
}



void
BFGAgent::recv(Packet* p, Handler* h) {
	struct hdr_cmn* ch = HDR_CMN(p);
	struct hdr_ip* ih = HDR_IP(p);

    if( !this->proto_enabled_ )
    {
        drop(p);
        return;
    }



	if (ch->ptype() == PT_BFG) {
		hdr_bfg* eh = HDR_BFG(p);

        //printf("%0.9f _%d_ Paquete de PRoGRAD [src:%d/type:%d/sn:%d]\n", CURRENT_TIME, local_address(), ih->saddr(), eh->type(), ch->uid());

        if( ih->daddr() != IP_BROADCAST && ih->daddr() != local_address())
        {
            printf("%0.9f _%d_ BFG Paquete no esta destinado a este nodo\n", CURRENT_TIME, local_address());
            drop(p);
            return;
        }

		switch(eh->type()) {
			case PAQUETE_FBLOOM:
				receive_bloom_filter(p);
                break;
            case PAQUETE_SUV:
                receive_suv(p);
                break;
            case PAQUETE_REQ:
                receive_request(p);
                break;
			case PAQUETE_DATOS:
				receive_data_packet(p);
                break;
		}

	} else if ((ih->saddr() == local_address()) && (ch->num_forwards() == 0)) {
		insert_packet(p);        
        printf("%0.9f _%d_ PRG Recibido de capa superior [Src:%d, Dst:%d, SeqNo: %d]\n", CURRENT_TIME, local_address(), ih->saddr(), ih->daddr(), ch->uid());
	} else {
		//fprintf (stderr,"\n4.- nodo %d pak %d  num %d, tipo %d\n",id, ch->uid(), ch->num_forwards(), HDR_CMN(p)->ptype());
		printf("%0.9f _%d_ Paquete recibido en este nodo\n", CURRENT_TIME, local_address());
	}
	drop(p);
}




void
BFGAgent::send_bloom_filter() {
	Packet* p = Packet::alloc();
	hdr_cmn *ch = HDR_CMN(p);
	hdr_ip *ih = HDR_IP(p);
	hdr_bfg *eh = hdr_bfg::access(p);

	memset(eh, 0, BFG_HDR_LEN);

    this->seq_num_++;

    ch->uid() = this->seq_num_;
	ch->ptype() = PT_BFG;
	ch->direction() = hdr_cmn::DOWN;
    ch->size() += IP_HDR_LEN + BFG_BFHDR_LEN;
	ch->error() = 0;
	ch->prev_hop_ = local_address();
	ch->next_hop() = IP_BROADCAST;
	ch->addr_type() = NS_AF_INET;
	ch->xmit_failure_ = bfg_mac_failed_callback;
	ch->xmit_failure_data_ = (void*) this;

	ih->saddr() = local_address();
	ih->daddr() = IP_BROADCAST;
	ih->sport() = RT_PORT;
	ih->dport() = RT_PORT;
	ih->ttl() = IP_DEF_TTL;

	eh->src() = local_address();
	eh->dst() = IP_BROADCAST;
	eh->type() = PAQUETE_FBLOOM;
    eh->seq_num() = this->seq_num_;

	//Copiamos valor por valor del filtro en la seccion data del encabezado	


    byte* fb_serialized = this->fb_tiempo_->serialize();
    memcpy(eh->bloom_filter(), fb_serialized, BF_SIZE);
    if(prDebug_)
    {
        printf("%0.9f _%d_ Filtro a serializar: %s\n", CURRENT_TIME, local_address(), this->fb_tiempo_->to_string().c_str());
        hexDump(fb_serialized, BF_SIZE, "FILTRO BLOOM SERIALIZADO");
    }

    //printf("%0.9f _%d_ PRG Enviando Bloom Filter\n", CURRENT_TIME, local_address());
    printf("%0.9f _%d_ TXBLF pro_bytes: %d\n", CURRENT_TIME, local_address(), ch->size());
	Scheduler::instance().schedule(target_, p, JITTER);
}




void
BFGAgent::receive_bloom_filter(Packet *p) {
	hdr_ip *ih = HDR_IP(p);
	hdr_bfg *eh = HDR_BFG(p);
    hdr_cmn *ch = HDR_CMN(p);

    printf("%0.9f _%d_ RXBLF bfg_bytes %d {%d}\n", CURRENT_TIME, local_address(), ch->size(), ih->saddr());
    //printf("%0.9f _%d_ PRG Recibiendo Bloom Filter\n", CURRENT_TIME, local_address());

    //No se añade la direccion del nuevo vecino, ya que esa información viene en el FB
    //this->fb_tiempo_->add(ih->saddr());

    CountingFilter *Fjt = CountingFilter::deserialize(eh->bloom_filter(), BF_SIZE, BF_BUCKETS_IN_FILTER, BF_HASH_FUNCTIONS, BF_MAX_COUNT);

    if(prDebug_){
        printf("%0.9f _%d_ Filtro deserializado: %s\n", CURRENT_TIME, local_address(), Fjt->to_string().c_str() );
        printf("%0.9f _%d_ BLF Antes de actualizar: ", CURRENT_TIME, local_address());
        this->fb_tiempo_->print();
    }


    std::list<PacketIdentifier>::const_iterator bufferEntry;
    double Prj=0.0, Pri=0.0;
    int paquetes_suv=0;
    list<PacketIdentifier> resume;

    for(bufferEntry=this->buffer_.begin(); bufferEntry!=this->buffer_.end(); ++bufferEntry){
        PacketIdentifier pi = *bufferEntry;
        Prj=pro_calc_prob(pi, *Fjt);
        Pri=pro_calc_prob(pi, *this->fb_tiempo_);
        if(prDebug_)
        {
            printf("%0.9f _%d_ PRG Para el paquete [%d->%d,%d,%u]\n", CURRENT_TIME, local_address(), pi.src_, pi.dst_, pi.seq_num_);
            printf("%0.9f _%d_ PRG Prj(%d) = %0.5f, Pri = %0.5f , THRESHOLD=%0.5f\n", CURRENT_TIME, local_address(),ih->saddr(), Prj, Pri, FORWARD_THRESHOLD);
        }

        /**
          * ESTRATEGIA DE FORWARDING
          */

        //if( Prj >= FORWARD_THRESHOLD || Prj == 1.0 )//Caminante 1
        if( Prj >= Pri + FORWARD_THRESHOLD || Prj == 1.0) //Caminante 2
        //if( Prj >= Pri + Pri*FORWARD_THRESHOLD || Prj == 1 ) //Caminante 3
        //if( Pri <= FORWARD_THRESHOLD || Prj >= Pri + FORWARD_THRESHOLD ) //Caminante 4
        {
            //printf("%0.9f _%d_ PRG Agregando al resumen a enviar\n", CURRENT_TIME, local_address());
            resume.push_back(pi);
            if(resume.size() == PACKETS_IN_SUV){
                //printf("%0.9f _%d_ PRG Resumen lleno, enviando SUV...\n", CURRENT_TIME, local_address());
                send_suv(ih->saddr(), resume);
                paquetes_suv++;
                resume.clear();
            }
        }
    }

    if(resume.size() != 0){
        printf("%0.9f _%d_ PRG Enviando ultimos _%lu_ paquetes en SUV a _%d_...\n", CURRENT_TIME, local_address(), resume.size(), ih->saddr());
        send_suv(ih->saddr(), resume);
        paquetes_suv++;
    }

    u_int32_t bytes_sent = (paquetes_suv*(IP_HDR_LEN + BFG_HDR_LEN)); //Los paquetes SUV son de tamaño constante

    printf("%0.9f _%d_ TXSUV bfg_bytes: %d [%d]\n", CURRENT_TIME, local_address(), bytes_sent, paquetes_suv);

    //Finalmente actualizamos la información local
    pro_actualiza_bf(*Fjt);

    if(prDebug_){
        printf("%0.9f _%d_ BLF Despues de actualizar: ", CURRENT_TIME, local_address());
        this->fb_tiempo_->print();
    }
}


void
BFGAgent::send_suv(nsaddr_t dest, list<PacketIdentifier> resume){

    Packet* out = Packet::alloc();
    hdr_cmn *och = HDR_CMN(out);
    hdr_ip  *oih = HDR_IP(out);
    hdr_bfg *oeh = HDR_BFG(out);

    memset(oeh, 0, BFG_HDR_LEN);

    this->seq_num_++;

    och->uid() = this->seq_num_;
    och->ptype() = PT_BFG;
    och->direction() = hdr_cmn::DOWN;
    och->error() = 0;
    och->prev_hop_ = local_address();
    och->next_hop() = dest;
    och->addr_type() = NS_AF_INET;
    och->xmit_failure_ = bfg_mac_failed_callback;
    och->xmit_failure_data_ = (void*) this;

    oih->saddr() = local_address();
    oih->daddr() = dest;
    oih->sport() = RT_PORT;
    oih->dport() = RT_PORT;
    oih->ttl() = IP_DEF_TTL;

    oeh->src() = local_address();
    oeh->dst() = dest;
    oeh->type() = PAQUETE_SUV;
    oeh->seq_num() = this->seq_num_;
    oeh->suv_qty() = resume.size();

    och->size() = IP_HDR_LEN + BFG_HDR_LEN;

    std::list<PacketIdentifier>::const_iterator entry;
    unsigned int index=0;
    for(entry=resume.begin(); entry != resume.end(); ++entry){
        oeh->summary_vector()[index++] = *entry;
    }

    Scheduler::instance().schedule(target_, out, JITTER);
}



void
BFGAgent::receive_suv(Packet *p){
    hdr_ip  *ih = HDR_IP(p);
    hdr_cmn *ch = HDR_CMN(p);
    hdr_bfg *eh = HDR_BFG(p);

    if(eh->suv_qty() == 0) return;
    if(eh->suv_qty() > PACKETS_IN_SUV) return;

    printf("%0.9f _%d_ RXSUV bfg_bytes %d\n", CURRENT_TIME, local_address(), ch->size());

    /****************************Preparacion de paquete REQ a enviar   *****************/
    Packet* out = Packet::alloc();
    hdr_cmn *och = HDR_CMN(out);
    hdr_ip  *oih = HDR_IP(out);
    hdr_bfg *oeh = HDR_BFG(out);

    memset(oeh, 0, BFG_HDR_LEN);


    this->seq_num_++;
    och->uid() = this->seq_num_;
    och->ptype() = PT_BFG;
    och->direction() = hdr_cmn::DOWN;
    och->error() = 0;
    och->prev_hop_ = local_address();
    och->next_hop() = ih->saddr();
    och->addr_type() = NS_AF_INET;
    och->xmit_failure_ = bfg_mac_failed_callback;
    och->xmit_failure_data_ = (void*) this;

    oih->saddr() = local_address();
    oih->daddr() = ih->saddr();
    oih->sport() = RT_PORT;
    oih->dport() = RT_PORT;
    oih->ttl() = IP_DEF_TTL;

    oeh->src() = local_address();
    oeh->dst() = ih->saddr();
    oeh->type() = PAQUETE_REQ;
    oeh->seq_num() = this->seq_num_;

    och->size() = IP_HDR_LEN + BFG_HDR_LEN;

    /*************************************************************************************/

    int request_index=0;
    for(int packet_index=0; packet_index<eh->suv_qty(); packet_index++){
        PacketIdentifier pi = eh->summary_vector()[packet_index];
        //Si el paquete no está en bufer, y no lo ha consumido entonces lo pide
        if(!check_packet_cache(pi)){
            //Integrar al paquete de peticion
            oeh->summary_vector()[request_index++]=pi;
            oeh->suv_qty_++;
        }
    }

    if(oeh->suv_qty() > 0){
        printf("%0.9f _%d_ TXREQ Recibidos %d ,pidiendo %d\n", CURRENT_TIME, local_address(), eh->suv_qty(), oeh->suv_qty());
        printf("%0.9f _%d_ TXREQ bfg_bytes: %d\n", CURRENT_TIME, local_address(), och->size());
        Scheduler::instance().schedule(target_, out, JITTER);
    }else{
        Packet::free(out);
    }
}


void
BFGAgent::receive_request(Packet *p){
    hdr_ip  *ih = HDR_IP(p);
    hdr_bfg *eh = HDR_BFG(p);
    hdr_cmn *ch = HDR_CMN(p);

    printf("%0.9f _%d_ RXREQ bfg_bytes %d\n", CURRENT_TIME, local_address(), ch->size());


    if(eh->suv_qty() == 0  || eh->suv_qty() > PACKETS_IN_SUV) return;

    for(int packet_index=0; packet_index<eh->suv_qty(); packet_index++){
        send_data_packet(eh->summary_vector()[packet_index], ih->saddr());
    }
}

void
BFGAgent::send_data_packet(PacketIdentifier pi, nsaddr_t dest){
    Packet* out = Packet::alloc();
    hdr_cmn *och = HDR_CMN(out);
    hdr_ip *oih = HDR_IP(out);
    hdr_bfg *oeh = HDR_BFG(out);

    memset(oeh, 0, BFG_HDR_LEN);

    this->seq_num_++;

    och->uid() = this->seq_num_;
    och->ptype() = PT_BFG;
    och->direction() = hdr_cmn::DOWN;
    och->error() = 0;
    och->prev_hop_ = local_address();
    och->next_hop() = dest;
    och->addr_type() = NS_AF_INET;
    och->xmit_failure_ = bfg_mac_failed_callback;
    och->xmit_failure_data_ = (void*) this;

    oih->saddr() = local_address();
    oih->daddr() = dest;
    oih->sport() = RT_PORT;
    oih->dport() = RT_PORT;
    oih->ttl() = IP_DEF_TTL;

    oeh->src() = local_address();
    oeh->dst() = dest;
    oeh->type() = PAQUETE_DATOS;
    oeh->seq_num() = this->seq_num_;


    och->size() = IP_HDR_LEN + BFG_HDR_LEN + pi.size_;
    oeh->summary_vector()[0]=pi;


    printf("%0.9f _%d_ TXDAT bfg_bytes: %d data_bytes:%d\n", CURRENT_TIME, local_address(), och->size() - pi.size_, pi.size_);

    Scheduler::instance().schedule(target_, out, JITTER);

}


void
BFGAgent::receive_data_packet(Packet *p) {
	hdr_bfg *eh = HDR_BFG(p);
    hdr_cmn *ch = HDR_CMN(p);

    PacketIdentifier pkt_rcvd=eh->summary_vector()[0];

    printf("%0.9f _%d_ RXDAT Recibido: %d bytes\n", CURRENT_TIME, local_address(), ch->size());


    if (check_packet_cache(pkt_rcvd)) {
        printf("%0.9f _%d_ iRXDAT Paquete ya existe en cache [Src:%d, Dst:%d, SeqNo: %d]\n", CURRENT_TIME, local_address(), pkt_rcvd.src_, pkt_rcvd.dst_, pkt_rcvd.seq_num_);
		return;
	}

    if (pkt_rcvd.dst_ == local_address()) {
        printf("%0.9f _%d_ iRXDAT Consumiendo paquete [Src:%d, Dst:%d, SeqNo: %d]\n", CURRENT_TIME, local_address(), pkt_rcvd.src_, pkt_rcvd.dst_, pkt_rcvd.seq_num_);
        add_to_cache(pkt_rcvd);
	} else {
        printf("%0.9f _%d_ iRXDAT Agregando paquete al buffer [Src:%d, Dst:%d, SeqNo: %d]....\n", CURRENT_TIME, local_address(), pkt_rcvd.src_, pkt_rcvd.dst_, pkt_rcvd.seq_num_);
        add_identifier_to_buffer(pkt_rcvd);
        add_to_cache(pkt_rcvd);
	}

}





/*::::::::::::::::::::::::::::::FUNCIONES DEL BUFFER::::::::::::::::::::::::::::::*/

/*Inserta el paquete de NS2 que se provee al buffer interno*/
void
BFGAgent::insert_packet(Packet *p) {
	//bool packet_exists = false;

	hdr_cmn *ch = HDR_CMN(p);
	hdr_ip *ih = HDR_IP(p);
	
	PacketIdentifier pi;
	pi.dst_      = ih->daddr();
	pi.dst_port_ = ih->dport();
	pi.seq_num_  = ch->uid();
	pi.size_     = ch->size();
	pi.src_      = ih->saddr();
	pi.src_port_ = ih->sport();

    if(this->buffer_.size() >= BUFFER_SIZE){
        printf("%0.9f _%d_ BUFFER lleno [Src:%d, Dst:%d, SeqNo: %d]....\n", CURRENT_TIME, local_address(), pi.src_, pi.dst_, pi.seq_num_);
        return;
    }

	if (!is_in_buffer(pi)) {
		buffer_.push_back(pi);
        add_to_cache(pi);
	}
}


/*
 * Esta funcion solamente es invocada cuando se agregan paquetes recibidos en
 * la ultima fase del protocolo. Esto da la garantía de que cualquier
 * identificador que entre, no existe en el buffer.
 * */
void
BFGAgent::add_identifier_to_buffer(PacketIdentifier p) {

    if(this->buffer_.size() >= BUFFER_SIZE){
        printf("%0.9f _%d_ BUFFER lleno [Src:%d, Dst:%d, SeqNo: %d]....\n", CURRENT_TIME, local_address(), p.src_, p.dst_, p.seq_num_);
        return;
    }

    if(!is_in_buffer(p))
        buffer_.push_back(p);
}


bool
BFGAgent::is_in_buffer(PacketIdentifier pi){
    std::list<PacketIdentifier>::const_iterator it;
	for(it=this->buffer_.begin(); it!=this->buffer_.end(); ++it){
        if(it->dst_ == pi.dst_ &&
		   it->dst_port_ == pi.dst_port_ &&
		   it->src_ == pi.src_ &&
		   it->src_port_ == pi.dst_port_ &&
           it->seq_num_ == pi.seq_num_)
            return true;
	}

	return false;
}

void
BFGAgent::dump_buffer(){
    std::list<PacketIdentifier>::const_iterator it;
    for(it=this->buffer_.begin(); it!=this->buffer_.end(); ++it){
		printf("%0.9f _%d_ BUFF [%d:%d/%d:%d/%d/%d]\n", CURRENT_TIME, local_address(),
				it->src_, it->src_port_,
				it->dst_, it->dst_port_,
				it->seq_num_, it->size_);
	}
    printf("_%d_ Hay %ld entradas en el buffer\n",local_address(), buffer_.size());
}


void
BFGAgent::add_to_cache(PacketIdentifier pi){
    this->cache_.insert(pi);
}

/**
 * @brief BFGAgent::check_packet_cache Comprueba la existencia de un paquete en la cache
 * @param pi El PacketIdentifier a comprobar en la cache
 * @return True si existe en la cache
 */
bool
BFGAgent::check_packet_cache(PacketIdentifier pi){

    const bool is_in = this->cache_.find(pi) != this->cache_.end();
    return is_in;
    /*
    std::list<PacketIdentifier>::const_iterator it;
    for(it=this->cache_.begin(); it!=this->cache_.end(); ++it){
        if(it->dst_      == pi.dst_ &&
           it->dst_port_ == pi.dst_port_ &&
           it->src_      == pi.src_ &&
           it->src_port_ == pi.src_port_ &&
           it->seq_num_  == pi.seq_num_)
            return true;
    }

    return false;
    */
}

/*__________________________________________________ FUNCIONES DEL PROTOCOLO______________________________________________*/


/**
 * Funcion que calcula la probabilidad de que un nodo relevo pueda entregar el paquete de informacion packet
 * ATENCION: En este caso el nodo local no calcula la probabilidad de entrega como se especifica en la ecuacion
 * 5.3, sino que, el nodo que calcula esta probabilidad es aquel que ha ercibido el filtro bloom de otro nodo.
 * @param packet Un paquete de informacion almacenado en el buffer interno de este nodo
 * @param relevo Un nodo que recientemente ha entablado una comunicación con este nodo
 * @return El valor de la probabilidad que tiene el nodo de entregar el paquete, en el rango [0,1]
 */
double
BFGAgent::pro_calc_prob(const PacketIdentifier &packet, CountingFilter &Fjt){

    double pr_Dj = 0.0; //La probabilidad de llegar al nodo D a través de j (el nodo donde se calcula es i)

    //cout << "--------------------- PROBABILIDAD  ----------------------------"<< endl;
    //D_est es el filtro bloom que contiene la direccion del nodo j
    std::vector<u_int32_t> indices = Fjt.hash_values_for(packet.dst_);

    double producto = 1.0;
    for (std::vector<u_int32_t>::const_iterator it = indices.begin(); it != indices.end(); ++it) {
        //cout << "x=" << *it << " , suma=" << suma << " , bucket=" << Fjt.get_counter_at(*it) << endl;
        producto *= Fjt.get_counter_at(*it);
    }

    pr_Dj = (double) producto / std::pow(BF_MAX_COUNT, BF_HASH_FUNCTIONS);
    //cout << "-----------------///// PROBABILIDAD  - " << pr_Dj	<< " -------------------------" << endl;
    return pr_Dj;
}

double
BFGAgent::probabilityTo(nsaddr_t dst) const
{
    double pr_Dj = 0.0;
    std::vector<u_int32_t> indices = this->fb_tiempo_->hash_values_for(dst);

<<<<<<< HEAD
#ifdef PRSUMA
    double suma = 0.0;
=======
    double producto = 1.0;
>>>>>>> 4a84a048582b45c72cab28c90670f52481412cb1
    for (std::vector<u_int32_t>::const_iterator it = indices.begin(); it != indices.end(); ++it) {
        producto *= this->fb_tiempo_->get_counter_at(*it);
    }

<<<<<<< HEAD
    pr_Dj = (double) suma / (BF_MAX_COUNT * BF_HASH_FUNCTIONS * 1.0);
#else
    double prod = 1.0;
    for (std::vector<u_int32_t>::const_iterator it = indices.begin(); it != indices.end(); ++it) {
        prod *= this->fb_tiempo_->get_counter_at(*it);
    }

    pr_Dj = (double) prod / ((double) std::pow(BF_MAX_COUNT, BF_HASH_FUNCTIONS));
#endif

=======
    pr_Dj = (double) producto / std::pow(BF_MAX_COUNT, BF_HASH_FUNCTIONS);
>>>>>>> 4a84a048582b45c72cab28c90670f52481412cb1
    return pr_Dj;
}

void
BFGAgent::debug_probability_to(nsaddr_t dst)
{
    double pr_Dj = 0.0;
    std::vector<u_int32_t> indices = this->fb_tiempo_->hash_values_for(dst);
    std::stringstream ss;
    if(!indices.empty())
    {
        for(size_t i = 0; i < indices.size(); ++i)
        {
            if(i != 0)
                ss << ",";
            ss << indices[i];
        }
    }
    std::string s = ss.str();
    printf("%0.9f _%d_ DBGP ProbabilityTo ID(%d) %s\n", CURRENT_TIME, local_address(), dst, s.c_str());

    double producto = 1.0;
    for (std::vector<u_int32_t>::const_iterator it = indices.begin(); it != indices.end(); ++it) {
        u_int32_t counter = this->fb_tiempo_->get_counter_at(*it);
        printf("%0.9f _%d_ DBGP ProbabilityTo BF[%d]=%d/%d\n", CURRENT_TIME, local_address(), *it, counter, BF_MAX_COUNT);
        producto *= counter;
    }
    pr_Dj = (double) producto / std::pow(BF_MAX_COUNT, BF_HASH_FUNCTIONS);
    printf("%0.9f _%d_ DBGP ProbabilityTo ID(%d) %0.4f\n", CURRENT_TIME, local_address(), dst, pr_Dj);
}



void
BFGAgent::print_bfrepr()
{
    std::vector<u_int32_t> v = this->fb_propio_->hash_values_for(local_address());
    std::stringstream ss;
    if(!v.empty())
    {
        for(size_t i = 0; i < v.size(); ++i)
        {
            if(i != 0)
                ss << ",";
            ss << v[i];
        }
    }
    std::string s = ss.str();
    printf("%0.9f _%d_ BF HashKeys: %s\n", CURRENT_TIME, local_address(), s.c_str());
}

/**
 * Una vez que un nodo recibe una actualizacion por parte de otro nodo, se debe actualizar el filtro Bloom interno
 * fb_tiempo_ para que tome en cuenta la informacion que se acaba de recibir.
 * Definido en la ecuacion 5.1
 * @param nuevo El filtro Bloom que recién se recibió.
 */
void
BFGAgent::pro_actualiza_bf(CountingFilter &nuevo){
    if(prDebug_)
    {
        printf("%0.9f _%d_ ACTUALIZACION FILTRO \n", CURRENT_TIME, local_address());
        printf("%0.9f _%d_ NUEVO : %s \n", CURRENT_TIME, local_address(), nuevo.to_string().c_str());
        printf("%0.9f _%d_ ACTUAL: %s \n", CURRENT_TIME, local_address(), this->fb_tiempo_->to_string().c_str());
    }

    //Degradar el filtro nuevo
    nuevo.degrada(PROBABILIDAD_DEGRADACION);

    *this->fb_tiempo_ += nuevo;

    if(prDebug_)
    {
        printf("%0.9f _%d_ Filtro propio actualizado\n", CURRENT_TIME, local_address());
        printf("%0.9f _%d_ %s\n", CURRENT_TIME, local_address(), this->fb_tiempo_->to_string().c_str());
    }
}

/**
 * Cada cierto tiempo, se debe de degradar el filtro que contiene la informacion de los contactos vistos, y se combina
 * con el filtro que contiene la direccion del nodo.
 * @brief BFGAgent::pro_degradacion_periodica
 */
void
BFGAgent::pro_degradacion_periodica(){
    //cout<<"#################### DEGRADACION PERIODICA " << local_address() <<" ################################"<<endl;
    this->fb_tiempo_->degrada(PROBABILIDAD_DEGRADACION);
    this->fb_tiempo_ = &(*this->fb_tiempo_ + *this->fb_propio_);
    //cout<<"#################### /DEGRADACION PERIODICA " << local_address() <<" ################################"<<endl;
}



/*__________________________________________________ FUNCIONES DE AYUDA______________________________________________*/


void
BFGAgent::print_bloomfilter(nsaddr_t dst){
    MobileNode *mn = (MobileNode*) Node::get_node_by_address(local_address());
    mn->update_position();
    double x=mn->X();
    double y=mn->Y();
    printf("%0.9f %d %0.3f %0.3f pBFG %0.3f %0.3f\n", CURRENT_TIME, local_address(), x, y, probabilityTo(dst), this->fb_tiempo_->saturation());
}


void
BFGAgent::hexDump(const unsigned char* buffer, int size_in_bytes, const char* msg) {
	int i, restante = size_in_bytes, imp, inicio, fin;

	printf("_%p_ %s - [DEBUG] %d bytes\n", buffer, msg, size_in_bytes);

	imp = size_in_bytes < 16 ? size_in_bytes : 16;
	inicio = 0, fin = imp;
	printf(
			"\033[4;34m              00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n");
	printf("\033[0m");
	while (restante) {
		printf("[%08X]    ", inicio);
		for (i = 0; i < imp; i++) {
			printf("%02X ", *(buffer + i + inicio));
		}
		printf("\n");
		inicio += imp, fin += imp;
		imp = restante < 16 ? restante : 16;
		restante -= imp;
	}
	printf("%s - [/DEBUG] \n", msg);
}

void
BFGAgent::asciiDump(const unsigned char* buffer, int size_in_bytes,	const char* msg) {
	int i, restante = size_in_bytes, imp, inicio, fin;

	printf("_%p_ %s - [DEBUG] %d bytes\n", buffer, msg, size_in_bytes);

	restante = size_in_bytes;
	imp = size_in_bytes < 16 ? size_in_bytes : 16;
	inicio = 0, fin = imp;
	printf("              00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n");
	while (restante) {
		printf("[%08X]    ", inicio);
		for (i = 0; i < imp; i++) {
			printf(" %c ", *(buffer + i + inicio));
		}
		printf("\n");
		inicio += imp, fin += imp;
		imp = restante < 16 ? restante : 16;
		restante -= imp;
	}

	printf("%s - [/DEBUG] \n", msg);
}
