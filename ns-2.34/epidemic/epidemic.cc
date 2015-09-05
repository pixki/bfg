#include "epidemic.h"
#include <random.h>
#include <cmu-trace.h>
#include <iostream>
#include <tclcl.h>

int hdr_epi::offset_;

static class EpidemicHeaderClass: public PacketHeaderClass {
public:
	EpidemicHeaderClass() :
			PacketHeaderClass("PacketHeader/Epidemic", sizeof(hdr_epi)) {
		bind_offset(&hdr_epi::offset_);
	}
} class_rtProtoEpidemic_hdr;

/*TCL Hook*/
static class EpidemicClass: public TclClass {

public:
	EpidemicClass() :
			TclClass("Agent/Epidemic") {
	}
	TclObject* create(int argc, const char* const * argv) {
		assert(argc == 5);
		return (new Epidemic((nsaddr_t) Address::instance().str2addr(argv[4])));
	}
} class_rtProtoEpidemic;

/*----------------------------------------------------------------------------------------------*/
/*Implementacion del timer para maenjar los paquetes hello                                      */
/*----------------------------------------------------------------------------------------------*/
void
EpidemicHelloTimer::handle(Event* e)
{
    if(!agent_->proto_enabled_) return;

	agent_->send_summary_vector();
	double interval = MinHelloInterval
			+ ((MaxHelloInterval - MinHelloInterval) * Random::uniform());
	assert(interval >= 0);
	//Nos aseguramos que exsta cierto desfase entre los nodos al enviar paquetes de hola
	Scheduler::instance().schedule(this, &intr_, interval);
}

void
EpidemicHelloTimer::cancel()
{
    Scheduler::instance().cancel(&intr_);
}






static void
epidemic_mac_failed_callback(Packet* p, void *arg) {
	((Epidemic*) arg)->mac_failed(p);
}



void
Epidemic::mac_failed(Packet* p) {
	struct hdr_cmn* ch = HDR_CMN(p);
	struct hdr_ip* ih = HDR_IP(p);

	switch (ch->xmit_reason_) {
	case 0: //ARP Max request reached
		printf("P %f _%d_ EPI --- MAC Error de ARP\n", CURRENT_TIME, local_address());
		break;

		//Los siguientes estand definidos en packet.h
		case XMIT_REASON_RTS://0x01 Too many RTS but no CTS
		printf("P %f _%d_ EPI --- MAC Error de RTS\n", CURRENT_TIME,local_address());
		break;
		case XMIT_REASON_ACK://0x02 No ACK received when transmitting data packet
		printf("P %f _%d_ EPI --- MAC Error de ACK\n", CURRENT_TIME,local_address());
		break;
	}

	if (ch->ptype() == PT_EPIDEMIC) {

		struct hdr_epi* eh = HDR_EPI(p);
		printf("P %f _%d_ EPI --- Error al enviar paquete de Epidemic en capa 2, [size:%d/src:%d/dst:%d/ids:%d/type:%d]\n", CURRENT_TIME, local_address(), ch->size(), eh->src(), eh->dst(), eh->id_qty(), eh->type());
	} else {
		printf("P %f _%d_ EPI --- Error al enviar paquete en capa 2, [%d/%d/%d/%d]\n", CURRENT_TIME, local_address(), ih->saddr(), ih->daddr(), ch->uid(), ch->size());
	}

	drop(p);
}

/**
 * Constructor del agente de Epidemic, se le proporciona la dirección de red que usará
 */
Epidemic::Epidemic(nsaddr_t id) :
		Agent(PT_EPIDEMIC), helloTimer_(this) {
	local_address() = id;
    this->proto_enabled_=false;
}



/*Especificación de comandos que recibirá desde el simulador el agente.*/
int
Epidemic::command(int argc, const char* const * argv) {
	if (argc == 2) {
		if (strcasecmp(argv[1], "start") == 0) {
			helloTimer_.handle((Event*) 0);
			return TCL_OK;
        }else if(strcasecmp(argv[1], "entersim")==0){
            if(!this->proto_enabled_)
            {
                this->proto_enabled_ = true;
                helloTimer_.handle((Event*) 0);
            }
            return TCL_OK;
        }else if(strcasecmp(argv[1], "stop") == 0){
            //Cancelar los timers del protocolo
            printf("%0.9f _%d_ CMD Deteniendo los timers y el funcionamiento del protocolo\n", CURRENT_TIME, local_address());
            helloTimer_.cancel();
            this->proto_enabled_ = false;
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
Epidemic::recv(Packet* p, Handler* h) {
	struct hdr_cmn* ch = HDR_CMN(p);
	struct hdr_ip* ih = HDR_IP(p);

    if( !this->proto_enabled_ )
    {
        drop(p);
        return;
    }


	if (ch->ptype() == PT_EPIDEMIC) {
		hdr_epi* eh = HDR_EPI(p);

		//printf("%0.9f _%d_ Paquete de epidemic [%d/%d]\n", CURRENT_TIME, local_address(), ih->saddr(), ch->uid());
		switch(eh->type()) {
			case SUV_PACKET:
				receive_summary_vector(p);
			break;
			case REQ_PACKET:
				//printf("%0.9f _%d_ RX REQ _%d_ pide %d paquetes locales\n", CURRENT_TIME, local_address(), ih->saddr(), eh->id_qty());
				receive_packets_request(p);
			break;
			case DAT_PACKET:
				//printf("%0.9f _%d_ RX DAT Recibo %d paquetes de _%d_\n", CURRENT_TIME, local_address(), eh->id_qty(), ih->saddr());
				receive_data_packets(p);
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
Epidemic::send_summary_vector() {


	//Evita mandar paquetes sin utilidad
	if (buffer_.size() == 0)
		return;



	/*
	 *list<EpiPacketIdentifier> suv = get_random_subset(PACKETS_PER_SUV); //Lista de paquetes aleatorios
     *
     * list<EpiPacketIdentifier> suv = get_all_packets_in_buffer(); //No importa la prioridad, manda todos

     *
	 */
    list<EpiPacketIdentifier> suv = get_packets_to_xmit(); // Con cola de prioridades

    while(!suv.empty()){

        Packet* p = Packet::alloc();
        hdr_cmn *ch = HDR_CMN(p);
        hdr_ip *ih = HDR_IP(p);
        hdr_epi *eh = HDR_EPI(p);
        memset(eh, 0, EPI_HDR_LEN);

        this->seq_num_++;

        ch->uid() = this->seq_num_;
        ch->ptype() = PT_EPIDEMIC;
        ch->direction() = hdr_cmn::DOWN;
        ch->size() += IP_HDR_LEN + EPI_HDR_LEN;
        ch->error() = 0;
        ch->prev_hop_ = local_address();
        ch->next_hop() = IP_BROADCAST;
        ch->addr_type() = NS_AF_INET;
        ch->xmit_failure_ = epidemic_mac_failed_callback;
        ch->xmit_failure_data_ = (void*) this;

        ih->saddr() = local_address();
        ih->daddr() = IP_BROADCAST;
        ih->sport() = RT_PORT;
        ih->dport() = RT_PORT;
        ih->ttl() = IP_DEF_TTL;

        eh->src() = local_address();
        eh->dst() = IP_BROADCAST;
        eh->type() = SUV_PACKET;
        eh->seq_num() = this->seq_num_;
        eh->id_qty()=0;

        u_int32_t limit = suv.size() < PACKETS_PER_SUV? suv.size() : PACKETS_PER_SUV;
        for (u_int32_t index=0; index < limit; ++index) {
            eh->id_[index] = suv.front();
             eh->id_qty()++;
            suv.pop_front();
        }
        printf("%0.9f _%d_ TXSUV epi_bytes: %d\n", CURRENT_TIME, local_address(), ch->size());
        Scheduler::instance().schedule(target_, p, JITTER);
    }
}




void
Epidemic::receive_summary_vector(Packet *p) {
	hdr_ip *ih = HDR_IP(p);
    hdr_cmn *ch = HDR_CMN(p);
	hdr_epi *eh = HDR_EPI(p);
	list<EpiPacketIdentifier> faltantes;

    printf("%0.9f _%d_ RXSUV Recibido: %d bytes\n", CURRENT_TIME, local_address(), ch->size());

	if (eh->id_qty() == 0)
		return;

	//BufferEntry rcvd;
	for (int i = 0; i < eh->id_qty(); i++) { //Se sabe que no superará el limite en PACKETS_PER_SUV

		/*
		rcvd.dst_id_ = eh->id_[i].dst_;
		rcvd.src_id_ = eh->id_[i].src_;
		rcvd.dst_port_ = eh->id_[i].dst_port_;
		rcvd.src_port_ = eh->id_[i].src_port_;
		rcvd.seq_num_ = eh->id_[i].seq_num_;
		rcvd.size_ = eh->id_[i].size_;
		rcvd.copies_ = 0;
		rcvd.inserted_at_ = CURRENT_TIME;
		*/
		if (!is_cached(eh->id_[i])) {
			faltantes.push_back(eh->id_[i]);
		}
	}

	if (faltantes.size() > 0)
		send_request_packet(ih->saddr(), faltantes);
}




void
Epidemic::send_request_packet(nsaddr_t dest,
		list<EpiPacketIdentifier> petition) {
	Packet* p = Packet::alloc();
	hdr_cmn *ch = HDR_CMN(p);
	hdr_ip *ih = HDR_IP(p);
	hdr_epi *eh = HDR_EPI(p);
	memset(eh, 0, EPI_HDR_LEN);

	this->seq_num_++;

	ch->uid() = this->seq_num_;
	ch->ptype() = PT_EPIDEMIC;
	ch->direction() = hdr_cmn::DOWN;
	ch->size() += IP_HDR_LEN + EPI_HDR_LEN;
	ch->error() = 0;
	ch->prev_hop_ = local_address();
	ch->next_hop() = dest;
	ch->addr_type() = NS_AF_INET;
	ch->xmit_failure_ = epidemic_mac_failed_callback;
	ch->xmit_failure_data_ = (void*) this;

	ih->saddr() = local_address();
	ih->daddr() = dest;
	ih->sport() = RT_PORT;
	ih->dport() = RT_PORT;
	ih->ttl() = IP_DEF_TTL;

	eh->src() = local_address();
	eh->dst() = dest;
	eh->type() = REQ_PACKET;
	eh->seq_num() = this->seq_num_;

	std::list<EpiPacketIdentifier>::const_iterator entry;
	int index = 0;
	for (entry = petition.begin(); entry != petition.end(); ++entry) {
		eh->id_[index++] = *entry;
	}
	eh->id_qty() = (u_int16_t) petition.size();

	printf("%0.9f _%d_ TXREQ epi_bytes: %d\n", CURRENT_TIME, local_address(), ch->size());
	Scheduler::instance().schedule(target_, p, JITTER);
}



/*
 * Se recibe un paquete pidiendo por N paquetes que tiene almacenados localmente este nodo
 *Crea el paquete de respuesta y lo envía.
 */
void
Epidemic::receive_packets_request(Packet *p) {
    hdr_cmn* ch = HDR_CMN(p);
	//hdr_ip* ih = HDR_IP(p);
	hdr_epi* eh = HDR_EPI(p);

    printf("%0.9f _%d_ RXREQ Recibido: %d bytes\n", CURRENT_TIME, local_address(), ch->size());


	if (eh->id_qty() == 0)
		return;

	for (int i = 0; i < eh->id_qty(); i++) {
		Packet* out = Packet::alloc();
		hdr_cmn *och = HDR_CMN(out);
		hdr_ip *oih = HDR_IP(out);
		hdr_epi *oeh = HDR_EPI(out);

		memset(oeh, 0, EPI_HDR_LEN);


		och->uid() = this->seq_num_++;
		och->ptype() = PT_EPIDEMIC;
		och->direction() = hdr_cmn::DOWN;
		och->error() = 0;
		och->prev_hop_ = local_address();
		och->next_hop() = IP_BROADCAST;
		och->addr_type() = NS_AF_INET;
		och->xmit_failure_ = epidemic_mac_failed_callback;
		och->xmit_failure_data_ = (void*) this;

		oih->saddr() = local_address();
		oih->daddr() = IP_BROADCAST;
		oih->sport() = RT_PORT;
		oih->dport() = RT_PORT;
		oih->ttl() = IP_DEF_TTL;

		oeh->src() = local_address();
		oeh->dst() = IP_BROADCAST;
		oeh->type() = DAT_PACKET;
		oeh->seq_num() = this->seq_num_;
		oeh->id_qty() = 1;

		och->size() = IP_HDR_LEN + EPI_HDR_LEN + eh->id_[i].size_;

		oeh->id_[0] = eh->id_[i];

		copy_created(eh->id_[i]);

		printf("%0.9f _%d_ TXDAT epi_bytes: %d data_bytes:%d\n", CURRENT_TIME, local_address(), och->size() - eh->id_[i].size_, eh->id_[i].size_);

        Scheduler::instance().schedule(target_, out, JITTER);
	}

}



void
Epidemic::receive_data_packets(Packet *p) {

	//hdr_cmn *ch = HDR_CMN(p);
	hdr_epi *eh = HDR_EPI(p);
	hdr_ip *ih = HDR_IP(p);
    hdr_cmn *ch = HDR_CMN(p);

    printf("%0.9f _%d_ RXDAT Recibido: %d bytes\n", CURRENT_TIME, local_address(), ch->size());

	if (ih->daddr() != IP_BROADCAST || eh->id_qty() != (u_int16_t)1) {
        printf("%0.9f _%d_ RXDAT Paquete no dirigido a este nodo\n",
				CURRENT_TIME, local_address());
		return;
	}

	if (is_cached(eh->id_[0])) {
        printf("%0.9f _%d_ RXDAT Paquete ya existe en cache/buffer\n", CURRENT_TIME, local_address());
		return;
	}


	EpiPacketIdentifier pkt_rcvd = eh->id_[0];


	update_cache(pkt_rcvd);//Sin importar si es para este nodo o no, se debe actualizar la cache

	if (pkt_rcvd.dst_ == local_address()) {
        printf("%0.9f _%d_ RXDAT Consumiendo paquete [Src:%d, Dst:%d, SeqNo: %d]\n", CURRENT_TIME, local_address(), pkt_rcvd.src_, pkt_rcvd.dst_, pkt_rcvd.seq_num_);
    } else {
		printf("%0.9f _%d_ RX DAT Agregando paquete al buffer Src:%d, Dst:%d, SeqNo: %d....\n", CURRENT_TIME, local_address(), pkt_rcvd.src_, pkt_rcvd.dst_, pkt_rcvd.seq_num_);
		add_identifier_to_buffer(pkt_rcvd);
	}

}





/*::::::::::::::::::::::::::::::FUNCIONES DEL BUFFER::::::::::::::::::::::::::::::*/

/*Inserta el paquete de NS2 que se provee al buffer interno*/
void
Epidemic::insert_packet(Packet *p) {
    //bool packet_exists = false;

	hdr_cmn *ch = HDR_CMN(p);
	hdr_ip *ih = HDR_IP(p);
	BufferEntry rcvd;

	rcvd.dst_id_ = ih->daddr();
	rcvd.src_id_ = ih->saddr();
	rcvd.dst_port_ = ih->dport();
	rcvd.src_port_ = ih->sport();
	rcvd.seq_num_ = ch->uid();
	rcvd.size_ = ch->size();
	rcvd.copies_ = 0;
    rcvd.inserted_at_ = CURRENT_TIME;

	EpiPacketIdentifier pi;
	pi.dst_ = rcvd.dst_id_;
	pi.dst_port_ = rcvd.dst_port_;
	pi.seq_num_ = rcvd.seq_num_;
	pi.size_ = rcvd.size_;
	pi.src_ = rcvd.src_id_;
	pi.src_port_ = rcvd.src_port_;



    if (!exists_in_buffer(rcvd) && !is_cached(pi)) {

        if(buffer_.size() >= BUFFER_SIZE){
            buffer_.sort();
            //Tiramos el paquete que tenga "más prioridad" (i.e. el más viejo si se usa OrderBufferByOldest)
            buffer_.pop();
        }

        buffer_.push(rcvd);
        update_cache(pi);
	}
}



bool
Epidemic::exists_in_buffer(BufferEntry p) {
	std::vector<BufferEntry>::const_iterator buff;

	//Al heredar de vector, puede seguirse iterando de esta forma, o
	//si se requiere ordenada se debe llamar:
	//       buffer_.sort()
	//antes de iterar
	for (buff = buffer_.begin(); buff != buffer_.end(); ++buff) {
		BufferEntry entry = *buff;
		if (entry.dst_id_ == p.dst_id_ && entry.src_id_ == p.src_id_
				&& entry.src_port_ == p.src_port_
				&& entry.dst_port_ == p.dst_port_
				&& entry.seq_num_ == p.seq_num_)
			return true;
	}
	return false;
}




bool
Epidemic::is_in_buffer(EpiPacketIdentifier pi) {
	BufferEntry be;
	be.dst_id_ = pi.dst_;
	be.dst_port_ = pi.dst_port_;
	be.src_id_ = pi.src_;
	be.src_port_ = pi.src_port_;
	be.copies_ = 0;
	be.seq_num_ = pi.seq_num_;
	return exists_in_buffer(be);
}




/*
 * Crea una lista con los identificadores de paquetes que deben de transmitirse, esto
 * aplica para cuando se esta haciendo una transmisión de paquete SUV
 */
list<EpiPacketIdentifier>
Epidemic::get_packets_to_xmit() {
	list<EpiPacketIdentifier> packets;
	std::vector<BufferEntry>::const_iterator buff;
	EpiPacketIdentifier tempId;

	//printf("%0.9f _%d_ PRIQ Obteniendo lista\n", CURRENT_TIME, local_address() );
	if (buffer_.size() <= PACKETS_PER_SUV) {//Copiamos todos los paquetes, ya que hay suficiente espacio
		for (buff = buffer_.begin(); buff != buffer_.end(); ++buff) {
			BufferEntry be = *buff;
			tempId.dst_ = be.dst_id_;
			tempId.dst_port_ = be.dst_port_;
			tempId.src_ = be.src_id_;
			tempId.src_port_ = be.src_port_;
			tempId.seq_num_ = be.seq_num_;
			tempId.size_ = be.size_;

			packets.push_back(tempId);
		}
	} else {
		buffer_.sort();
		//Copia los PACKETS_PER_SUV con mayor prioridad
		for (buff = buffer_.begin(); buff != buffer_.end(); ++buff) {
			BufferEntry be = *buff;
			if (packets.size() == PACKETS_PER_SUV)
				break;

			tempId.dst_ = be.dst_id_;
			tempId.dst_port_ = be.dst_port_;
			tempId.src_ = be.src_id_;
			tempId.src_port_ = be.src_port_;
			tempId.seq_num_ = be.seq_num_;
			tempId.size_ = be.size_;
			/*
			if(local_address() == 0){
				printf("%0.9f _%d_ PRIQ     Paq. %d, Cop. %d, Ins. %0.9f\n", CURRENT_TIME, local_address(), be.seq_num_, be.copies_, be.inserted_at_ );
			}
			*/

			packets.push_back(tempId);
		}
	}

	if(local_address() == 0){
		printf("%0.9f _%d_ PRIQ Se enviarán %ld\n", CURRENT_TIME, local_address(), packets.size() );
	}

	return packets;
}



list<EpiPacketIdentifier>
Epidemic::get_all_packets_in_buffer() {
    list<EpiPacketIdentifier> packets;
    std::vector<BufferEntry>::const_iterator buff;
    EpiPacketIdentifier tempId;

    for (buff = buffer_.begin(); buff != buffer_.end(); ++buff) {
        BufferEntry be = *buff;
        tempId.dst_ = be.dst_id_;
        tempId.dst_port_ = be.dst_port_;
        tempId.src_ = be.src_id_;
        tempId.src_port_ = be.src_port_;
        tempId.seq_num_ = be.seq_num_;
        tempId.size_ = be.size_;

        packets.push_back(tempId);
    }


    return packets;
}



/*
 * Incrementa el contador de copias dentr del buffer para el identificador de paquete
 * que se provee como parametro.
 * */
void
Epidemic::copy_created(EpiPacketIdentifier pi) {
	std::vector<BufferEntry>::iterator buffEntry;
	printf("%0.9f _%d_ BUFF Copia transmitida de %d-%d-%d\n", CURRENT_TIME, local_address(), pi.src_, pi.dst_, pi.seq_num_);
	for (buffEntry = buffer_.begin(); buffEntry != buffer_.end(); ++buffEntry) {
		if (pi.dst_ == buffEntry->dst_id_ && pi.src_ == buffEntry->src_id_
				&& pi.dst_port_ == buffEntry->dst_port_
				&& pi.src_port_ == buffEntry->src_port_
				&& pi.seq_num_ == buffEntry->seq_num_) {
			printf("%0.9f _%d_ BUFF Estado: %d-%d-%d-%d\n", CURRENT_TIME, local_address(), buffEntry->src_id_, buffEntry->dst_id_, buffEntry->seq_num_, buffEntry->copies_);
			buffEntry->copies_++;
			return;
		}
	}
}

/*
 * Esta funcion solamente es invocada cuando se agregan paquetes recibidos en
 * la ultima fase del protocolo epidemic. Esto da la garantía de que cualquier
 * identificador que entre, no existe en el buffer.
 * */
void
Epidemic::add_identifier_to_buffer(EpiPacketIdentifier p) {
	BufferEntry e;
	e.copies_ = 0;
	e.dst_id_ = p.dst_;
	e.dst_port_ = p.dst_port_;
	e.inserted_at_ = CURRENT_TIME;
	e.seq_num_ = p.seq_num_;
	e.size_ = p.size_;
	e.src_id_ = p.src_;
	e.src_port_ = p.src_port_;

	buffer_.push(e);
}

void
Epidemic::dump_buffer(){
	std::vector<BufferEntry>::const_iterator be;
		printf("_%d_ ----===BUFFER DUMP[%ld]===----\n", local_address(), buffer_.size());
		printf("%-5s%-5s%-5s%-5s%-10s\n", "SRC", "DST", "SEQ", "COP", "TIME");
		buffer_.sort();
		for(be = buffer_.begin(); be != buffer_.end(); ++be){
			printf("%d:%d\t %d:%d\t %d\t %d\t %-5.5f\n", be->src_id_, be->src_port_, be->dst_id_, be->dst_port_, be->seq_num_, be->copies_, be->inserted_at_);
		}
		printf("------------------------------\n");
}

/*::::::::::::::::::::::::::::::FUNCIONES DEL CACHE::::::::::::::::::::::::::::::*/

/*
 *Inserta el descriptor de paquete en el buffer de caché para indicar el ultimo paquete recibido
 */
void
Epidemic::update_cache(EpiPacketIdentifier p) {
	CacheEntry ce;
	ce.dst_ = p.dst_;
	ce.src_ = p.src_;
	ce.seq_num_ = p.seq_num_;

	//Encontrar la entrada en cache y actualizar al num de secuencia actual
	std::list<CacheEntry>::iterator cacheEntry;
	for (cacheEntry = cache_.begin(); cacheEntry != cache_.end(); ++cacheEntry) {

		if(cacheEntry->seq_num_ < ce.seq_num_) {
			continue;
		}


		if (cacheEntry->dst_ == ce.dst_ && cacheEntry->src_ == ce.src_ && cacheEntry->seq_num_ == ce.seq_num_) {
			 return;
		}

		//Si llega aqui, entonces la entrada no existe en la cache, y hay que insertarla
		if(cacheEntry->seq_num_ > ce.seq_num_){
			cache_.insert(cacheEntry, ce); //Se inserta antes del iterador cacheEntry
			printf("%0.9f _%d_ CACHE Entrada agregada, |C|=%ld\n", CURRENT_TIME, local_address(), cache_.size());
			return;
		}
	}
	cache_.push_back(ce);
	//En caso de que esté vacia la cache, se pone como default
}

/**
 * Devuelve VERDADERO si el numero de secuencia del "flujo" proporcionado es mayor que
 * el registrado en la cache.
 */
bool
Epidemic::is_cached(EpiPacketIdentifier pi) {
	std::list<CacheEntry>::const_iterator cacheEntry;
	for (cacheEntry = cache_.begin(); cacheEntry != cache_.end(); ++cacheEntry) {
		if (cacheEntry->dst_ == pi.dst_ &&
			cacheEntry->src_ == pi.src_ &&
			cacheEntry->seq_num_ == pi.seq_num_) {
			//printf("%0.9f _%d_ CACHE Paq. encontrado en la cache\n", CURRENT_TIME, local_address());
			return true;
		}
	}
	//Si no está en la cache
	return false;
}



void
Epidemic::dump_cache(){
	std::list<CacheEntry>::const_iterator ce;
	printf("_%d_ ----===CACHE DUMP===----\n", local_address());
	for(ce = cache_.begin(); ce != cache_.end(); ++ce){
		printf("%d/%d/%d\n", ce->src_, ce->dst_, ce->seq_num_);
	}
	printf("------------------------------\n");
}

/*__________________________________________________ FUNCIONES DE AYUDA______________________________________________*/

void
Epidemic::hexDump(const unsigned char* buffer, int size_in_bytes,
		const char* msg) {
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
Epidemic::asciiDump(const unsigned char* buffer, int size_in_bytes,
		const char* msg) {
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

list<EpiPacketIdentifier>
Epidemic::get_random_subset(int subset_size) {
	double probability = 0.0;
	double ran_val = 0.0;
	size_t left = buffer_.size();
	int to_choose = subset_size;
	std::vector<BufferEntry>::const_iterator packet;
	list<EpiPacketIdentifier> subset;

	srand(time(NULL));

	//printf("--------------------------\n");

	for (packet = buffer_.begin(); packet != buffer_.end(); ++packet) {
		probability = ((double) to_choose) / ((double) left);
		ran_val = (rand() % 100) / 100.0;

		//printf("Probabilidad: %d/%d (%f)\n",to_choose, left, probability);
		//printf("Tirada: %f\n", ran_val);
		if (ran_val <= probability && packet->copies_ < MAX_NUMBER_OF_COPIES) {

			//printf("   Escogido\n");
			EpiPacketIdentifier pi;
			pi.dst_ = packet->dst_id_;
			pi.dst_port_ = packet->dst_port_;
			pi.seq_num_ = packet->seq_num_;
			pi.size_ = packet->size_;
			pi.src_ = packet->src_id_;
			pi.src_port_ = packet->src_port_;

			subset.push_back(pi);

			if (--to_choose <= 0)
				break;
			//printf("Continuando\n");
		}

		left--;
	}
	printf("%0.9f _%d_ Se regresa un subconjunto de %ld elementos\n", CURRENT_TIME, local_address(), subset.size());

	return subset;
}

