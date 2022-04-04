import datetime
import socket
import time
import unbound

ctx = unbound.ub_ctx()
ctx.resolvconf("/etc/resolv.conf")
#status, result = ctx.resolve("www.nic.cz", unbound.RR_TYPE_A, unbound.RR_CLASS_IN)


FAKE_IPADDR = "18.163.23.97"
PORT = 9000

def init(id, cfg): return True
def deinit(id): return True
def inform_super(id, qstate, superqstate, qdata): return True

def is_good(qstate):
    status=-1
    if qstate.qinfo.qtype  != RR_TYPE_A:       return True
    log_info("Domain name :" + qstate.qinfo.qname_str)
    log_info("q-type : " + str(qstate.qinfo.qtype))
    log_info("q-class : " + str(qstate.qinfo.qclass ))
    log_info("q-return_msge:" + str(qstate.return_msg.rep.flags))
    log_info("q-return :" + str(qstate.return_rcode))

    if qstate.qinfo.qclass != RR_CLASS_IN:     return True
    if not qstate.return_msg:                  return False
    if (qstate.return_rcode) != RCODE_NOERROR: return True

    qflags = qstate.return_msg.rep.flags

    if  qflags == 0x8180:  return True
    log_info("flag :" + str(qflags))
    log_info("number of return mes:"+ str(qstate.return_msg.rep.an_numrrsets))

   #if qstate.return_msg.rep.an_numrrsets > 0 and qstate.return_msg.rep.rrsets[0].rk.type_str =="CNAME" :
   #     status, result = ctx.resolve(qstate.return_msg.rep.rrsets[0].rk.dname_str, unbound.RR_TYPE_A, unbound.RR_CLASS_IN)
   #     log_info(" return domain_name "+ str(qstate.return_msg.rep.rrsets[0].rk.dname_str )+":class: "+ str(qstate.return_msg.rep.rrsets[0].rk.rrset_class_str ))
   # if status == 0 and result.havedata:
   #     FAKE_IPADDR = str(result.data.address_list[0])
   #     log_info("IP of cname is : " + FAKE_IPADDR )

                #str(result.data.address_list) )
   #    return True

    if qflags == 0x8083 or  qflags == 0x8183:  return False
    if qflags != 0x8080 and qflags != 0x8180:  return True
    if qstate.return_msg.rep.an_numrrsets > 0: return True

    return False

def operate(id, event, qstate, qdata):

    if (event == MODULE_EVENT_NEW) or (event == MODULE_EVENT_PASS):
        #pass the query to validator
        qstate.ext_state[id] = MODULE_WAIT_MODULE
        return True

    if event == MODULE_EVENT_MODDONE:
        qtyp  = qstate.qinfo.qtype
        qname = qstate.qinfo.qname_str
        qstate.ext_state[id] = MODULE_FINISHED    # ..assume good


        if qstate.return_msg.rep.an_numrrsets > 0 and qstate.return_msg.rep.rrsets[0].rk.type_str =="CNAME" :
            status, result = ctx.resolve(qstate.return_msg.rep.rrsets[0].rk.dname_str, unbound.RR_TYPE_A, unbound.RR_CLASS_IN)
            if status == 0 and result.havedata:
                cname_ip = str(result.data.address_list[0])
                log_info(str(id) + " return domain_name "+ str(qstate.return_msg.rep.rrsets[0].rk.dname_str )+":before cname- : "+ str(qname)+":"+cname_ip )
                msg = DNSMessage(qname, qtyp, RR_CLASS_IN, PKT_QR | PKT_RA) # | PKT_AA)  # AA cannot be cached
                msg.answer.append("%s %d IN A %s" % (qname, 0,result.data.address_list[0]))  # ..ttl, ipaddr
                # ALL OK..
   # TRY TO SEND IT..
                qstate.ext_state[id] = MODULE_ERROR       # ..assume fail


                if not msg.set_return_msg(qstate): return True
                if not storeQueryInCache(qstate, qstate.return_msg.qinfo, qstate.return_msg.rep, 0): return False

                qstate.return_rcode = RCODE_NOERROR
                qstate.return_msg.rep.security = sec_status_secure
                qstate.ext_state[id] = MODULE_FINISHED    # ..assume good
                return True


        # TRY TO SKIP ALL EXCEPT "IN A" FAILED OR EMPTY RESPONSES..
        if is_good(qstate): return True

        if qstate.return_msg.rep.an_numrrsets == 0 and qstate.return_msg.rep.rrsets[0].rk.type_str =="CNAME" : return True

        qtyp  = qstate.qinfo.qtype
        qname = qstate.qinfo.qname_str


        # CREATE FAKE RESPONSE..
        log_info(str(id)+":NXforward: handle \"%s\"" % qname)

        date_time = datetime.datetime.now()

        # list_domains = open("/etc/unbound/list_qname.txt", "a")
        # print(date_time,"||", qstate.return_msg.qinfo.qname_str, file=list_domains)
        # list_domains.close()

        # expect there is linux NC command running on port 9000 to 9009 on FAKE-IP
        # "domain {query-domain-name}" is send to remote host to generate cert and NGINX

        if len(qname.split(".")) > 2:
            global PORT
            if PORT == 9009:
                PORT = 9000
            else:
                PORT += 1
            log_info("Handled by port " + str(PORT))
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            try:
                s.connect((FAKE_IPADDR, PORT))
                res = s.sendall(str.encode("domain " + qstate.return_msg.qinfo.qname_str[:-1]))
                if res == None:
                    s.close()
                    time.sleep(0.8)
                    # wait 0.8s for digi cert generation
            except:
                s.close()

        msg = DNSMessage(qname, qtyp, RR_CLASS_IN, PKT_QR | PKT_RA) # | PKT_AA)  # AA cannot be cached
        msg.answer.append("%s %d IN A %s" % (qname, 0, FAKE_IPADDR))  # ..ttl, ipaddr

        # TRY TO SEND IT..
        qstate.ext_state[id] = MODULE_ERROR       # ..assume fail


        if not msg.set_return_msg(qstate): return True
        if not storeQueryInCache(qstate, qstate.return_msg.qinfo, qstate.return_msg.rep, 0): return False

        # ALL OK..
        qstate.return_rcode = RCODE_NOERROR
        qstate.return_msg.rep.security = sec_status_secure
        qstate.ext_state[id] = MODULE_FINISHED    # ..assume good
        return True

    qstate.ext_state[id] = MODULE_ERROR
    return True
log_info("NXforward: loaded.")
