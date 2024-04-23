#include <iostream>
#include <algorithm>

#include "_lib.h/libHashSE.h"
#include "_base_tools/tool_TLS.h"

#include "triller/H12_flow.h"

using namespace std;

const int MIN_REQUEST = 60;

TLS_flow_creator::TLS_flow_creator(packet_statistics_object_type type, std::string fname, 
                    std::string filter, int thre, int header)
{
    pso_type = type;
    str_filter = filter;
    tls_pck_thre = thre;
    tls3_header = header;

    str_pcap = fname;
    str_tls = fname + ".TLS.fragment.csv";
    open_csv(str_tls);
    str_seg = fname + ".ADU.segment.csv";
    open_csv(str_seg);
    str_sort = fname + ".ADU.sorted.csv";

    lp_path_data = NULL;
}

TLS_flow_creator::~TLS_flow_creator()
{

}

IFlow2Object* TLS_flow_creator::create_Object(uint8_t* buf, int len)
{
    TLS_flow* lpFlow = new TLS_flow(buf, len, this);
    return lpFlow;
}

bool TLS_flow_creator::open_csv(std::string str_name)
{
    bool bout = false;
    FILE* fp = fopen(str_name.c_str(), "wt");
    if(fp)
    {
        fclose(fp);
        bout = true;
    }
    else
        cout << "open file error, file:" << str_name << endl;
    
    return bout;
}

void TLS_flow_creator::add_ADU(std::string str_sni, stt_ADU_TLS st_ADU)
{
    vct_ADU.push_back(st_ADU);
    if(lp_path_data)
        lp_path_data->add_segment(str_sni, st_ADU);
}

bool TLS_flow_creator::save_ADU_sorted()
{
    bool bout = false;
    if(vct_ADU.size() > 0)
    {
        sort(vct_ADU.begin(), vct_ADU.end(), [](stt_ADU_TLS stta, stt_ADU_TLS sttb){return stta.c_time < sttb.c_time;});
        bout = true;
    }    
    return bout;
}

//==============================================================================
//==============================================================================
//==============================================================================

TLS_flow::TLS_flow(uint8_t* buf, int len, TLS_flow_creator* lpFC)
{
    cntPck = cntSPck = 0;
    lpCreator = lpFC;

    if(len>0)
    {
        lenKey = len;
        bufKey = (uint8_t*)calloc(lenKey, sizeof(uint8_t));
        if(bufKey)
            memcpy(bufKey, buf, len);
    }

    bTLS = b_http_web = false;
    TLS_FR_c = CTLSFragCreator::create_TLS_fragmentation(65536);
    TLS_FR_s = CTLSFragCreator::create_TLS_fragmentation(2097152);
    cur_c_fragment = cur_s_fragment = NULL;
    bErrorData = false;
    bBaseSequence = false;
}

TLS_flow::~TLS_flow()
{
    if(bufKey)
        free(bufKey);
    if(TLS_FR_c)
        delete TLS_FR_c;
    if(TLS_FR_s)
        delete TLS_FR_s;
}

bool TLS_flow::addPacket(CPacket* lppck, bool bSou)
{
    bool bout = false;
    uint32_t seq = 0;
    int seq_pos = 0;

    if(lppck)
    {
        bout = true;
        if(lppck->getProtocol()==6 && !bErrorData)
        {
            int len;

            if(bSou)
                seq = lppck->getAckSeq();
            else
                seq = lppck->getAckSeq()+lppck->getLenPayload();
            
            {
                if(!bTLS)
                {
                    if(cntPck<200)
                    {
                        int iContent = checkTLSContent(lppck);
                        if(iContent > 0)
                        {
                            unsigned char *buffer = lppck->getPacketPayload(len);
                            if(iContent==0x16)    //handshake
                            {
                                if(bSou && isTLSClienthello(buffer, len))
                                {
                                    bTLS = true;
                                    setBaseSeq(lppck, true);
                                    char sname[UINT8_MAX];
                                    if(get_CH_SNI(buffer, len, sname) == 1)
                                    {
                                        strServer = sname;
                                    }
                                    getServerInfo(lppck, false);
                                }
                                else if(!bSou && isTLSServerhello(buffer, len))
                                {
                                    bTLS = true;
                                    setBaseSeq(lppck, false);
                                    strServer = "N/A";
                                    getServerInfo(lppck, true);
                                }
                            }
                            else if(iContent==0x17)
                            {
                                if(isTLSApplicationData(buffer, len))
                                {
                                    if(bSou && lppck->getDstPort()==443)
                                    {
                                        bTLS = true;
                                        setBaseSeq(lppck, true);
                                        strServer = "N/A";
                                        getServerInfo(lppck, false);
                                    }
                                }
                            }
                        }
                        else if(lppck->getSrcPort() == 443 && !bSou)
                        {
                            seq_pos = search_TLS_flag(lppck);
                            if(seq_pos > 0)
                            {
                                bTLS = true;
                                setBaseSeq(lppck, false);
                                strServer = "N/A";
                                getServerInfo(lppck, true);
                            }
                        }
                    }
                    if(bTLS)
                    {
                        bool b1, b2;
                        b1 = TLS_FR_c->initBuffer();
                        b2 = TLS_FR_s->initBuffer();
                        if(seq_pos>0)
                            TLS_FR_s->initFragmentData(seq_pos);
                        if(!b1 || !b2)
                        {
                            char buf_IPP[200];
                            CPacketTools::getStr_IPportpair_from_hashbuf(bufKey, lenKey, buf_IPP);
                            cout << buf_IPP << "init buffer error!!!" << endl;
                            bErrorData = true;
                        }
                    }

                }
                if(bTLS)
                {
                    bool bLastP;
                    unsigned char *buffer = lppck->getPacketPayload(len);

                    int seq_c, seq_s;
                    int size_omission;
                    if(bSou)                                //C->S
                    {
                        //stt_client_request stcr;
                        calPckSeq(lppck->getSelfSeq(), lppck->getAckSeq(), seq_c, seq_s);
                        if(seq_c >= 0)
                        {
                            size_omission = TLS_FR_c->setPckPayload_into_buffer(buffer, len, seq_c, bLastP);
                            if(size_omission < 0)//Insufficient memory, data loss
                                bErrorData = true;
                            else
                            {
                                if(bLastP && cur_c_fragment)
                                    cur_c_fragment->setLastPacket(lppck->getPckOffTime(), lppck->getPckNum());
                            }
                            checkFragmentRecover(TLS_FR_c, &vctTLSFragments, lppck->getPckOffTime(), lppck->getPckNum(), bSou, cntSPck, seq, true); 
                        }
                    }
                    else                                    //S->C
                    {
                        calPckSeq(lppck->getAckSeq(), lppck->getSelfSeq(), seq_c, seq_s);
                        if(seq_s >= 0)
                        {
                            cntSPck ++;

                            if(lppck->getLenPck() > MTU_value)
                                MTU_value = lppck->getLenPck();
                            if(lppck->getLenPck() == MTU_value && cur_s_fragment)
                                cur_s_fragment->add_MTU_pck();
                            if(lppck->getLenPayload()>500 && lppck->getLenPayload()<1000 && cur_s_fragment)
                                cur_s_fragment->add_MTU_PSH();
                            bool b_new_tls_pck;
                            if(buffer[0]==0x17 && buffer[1]==3 && buffer[2]==3)
                                b_new_tls_pck = true;
                            else
                                b_new_tls_pck = false;

                            size_omission = TLS_FR_s->setPckPayload_into_buffer(buffer, len, seq_s, bLastP);
                            if(size_omission < 0)//Insufficient memory, data loss
                                bErrorData = true;
                            else
                            {
                                if(bLastP && cur_s_fragment)
                                    cur_s_fragment->setLastPacket(lppck->getPckOffTime(), lppck->getPckNum());
                            }
                            checkFragmentRecover(TLS_FR_s, &vctTLSFragments, lppck->getPckOffTime(), lppck->getPckNum(), bSou, cntSPck, seq, b_new_tls_pck); 
                        }
                    }
                }
            }
        }
    }
    return bout;
}

bool TLS_flow::saveObject(FILE* fp, uint64_t cntP, bool bFin)
{
    bool bout = false;
    char buf_IPP[UINT8_MAX];
    if(fp)
    {
        if(bTLS && cntPck>=lpCreator->get_TLS_thre() && 
            (lpCreator->get_filter().length()==0 || strServer.find(lpCreator->get_filter())!=strServer.npos))
        {
            TLS_fragment *lpFrag;
            tls_ver = TLS_FR_s->get_TLS_version();

            CPacketTools::getStr_IPportpair_from_hashbuf(bufKey, lenKey, buf_IPP);
            fprintf(fp, "Info.,%s,SNI,%s,,,Pck.,%u,ver,%d\n", 
                    buf_IPP, strServer.c_str(), cntPck, tls_ver);        

            string strPck = "packet", strTime = "time", strFrag_c = "Fragment_c", strFrag_s = "Fragment_s";
            for(vector<TLS_fragment*>::iterator iter=vctTLSFragments.begin(); iter!=vctTLSFragments.end(); ++iter)
            {
                lpFrag = *iter;
                if(lpFrag)
                {
                    bool btype = true;

                    if(!btype || lpFrag->getTLSType()==23)
                    {
                        if(lpFrag->getBeginPckNo() == lpFrag->getEndPckNo())
                        {
                            strPck += "," + to_string(lpFrag->getEndPckNo());
                            strTime += "," + to_string(lpFrag->getEndTime());
                        }
                        else
                        {
                            strPck += "," + to_string(lpFrag->getBeginPckNo()) + "_" + to_string(lpFrag->getEndPckNo());
                            strTime += "," + to_string(lpFrag->getBeginTime()) + "_" + to_string(lpFrag->getEndTime());
                        }

                        if(lpFrag->isClient())
                        {
                            strFrag_c += "," + to_string(lpFrag->getFragmentLen());
                            strFrag_s += ",";
                        }
                        else
                        {
                            strFrag_s += "," + to_string(lpFrag->getFragmentLen());
                            strFrag_c += ",";
                        }
                    }
                }
            }
            fprintf(fp, "%s\n", strPck.c_str());
            fprintf(fp, "%s\n", strTime.c_str());
            fprintf(fp, "%s\n", strFrag_s.c_str());
            fprintf(fp, "%s\n", strFrag_c.c_str());
            fprintf(fp, "\n");
            bout = true;

            if(lpCreator->get_filter().length()==0 || strServer.find(lpCreator->get_filter())!=strServer.npos)
            {
                string strStat = lpCreator->getStat();
                FILE* fpStat = fopen(strStat.c_str(), "at");
                if(fpStat)
                {
                    fprintf(fpStat, "Info.,%sPck.,%u,,SNI,%s,,,,s_pck,%d,ver,%d\n", 
                            buf_IPP, cntPck, strServer.c_str(), cntSPck, tls_ver);  

                    char str_info[500];      
                    sprintf(str_info, "Info.,%sPck.,%u,,SNI,%s,,,,s_pck,%d,ver,%d", 
                            buf_IPP, cntPck, strServer.c_str(), cntSPck, tls_ver);        

                    fprintf(fpStat, "c_no,c_time,s_no,s_b_tm,s_e_tm,packet,,c_frag,c_len,,s_frag,s_len,s_first_TLS,s_TLS_max,s_TLS_min,s_estimate\n");
                    saveStat(fpStat);
                    fclose(fpStat);
                }
            }
        }
    }
    return bout;
}


void TLS_flow::saveStat(FILE* fp)
{
    TLS_fragment *lpFrag;
    stt_ADU_TLS stt_seg;
    int ifrag = 0;
    int len_header;
    if(tls_ver == 3)
    {
        int len = lpCreator->get_TLS3_header_len();
        if(len <= 0)
            len_header = 22;
        else
            len_header = len;
    }
    else
        len_header = 29;

    for(vector<TLS_fragment*>::iterator iter=vctTLSFragments.begin(); iter!=vctTLSFragments.end(); ++iter)
    {
        lpFrag = *iter;
        if(lpFrag)
        {
            if(ifrag == 0)
            {
                if(lpFrag->getTLSType()==23 && lpFrag->isClient())
                {
                    ifrag = 1;
                    init_segment(&stt_seg);
                    stt_seg.c_fragment = 1;
                    stt_seg.c_length = lpFrag->getFragmentLen();
                    stt_seg.c_no = lpFrag->getEndPckNo();
                    //stt_seg.c_port = cport;
                    stt_seg.c_time = lpFrag->getEndTime();
                    stt_seg.s_pk_begin = lpFrag->get_s_pkn();
                }
            }
            else if(ifrag == 1)
            {
                if(lpFrag->getTLSType()==23 && lpFrag->isClient())
                {
                    stt_seg.c_fragment ++;
                    stt_seg.c_length += lpFrag->getFragmentLen();
                }
                else if(lpFrag->getTLSType()==23 && !lpFrag->isClient())
                {
                    ifrag = 2;
                    stt_seg.s_length = stt_seg.s_first_frag = lpFrag->getFragmentLen();
                    if(lpFrag->getFragmentLen()>len_header)
                        stt_seg.s_estimate = lpFrag->getFragmentLen() - len_header;
                    else
                        stt_seg.s_estimate = 0;
                    if(lpFrag->getFragmentLen()>500 && lpFrag->getFragmentLen()<1800)
                    {
                        stt_seg.s_estimate2 = 0;
                        stt_seg.i_flag = 0;
                    }
                    else
                    {
                        stt_seg.s_estimate2 = stt_seg.s_estimate;
                        stt_seg.i_flag = 1;
                    }

                    stt_seg.s_fragment = 1;
                    stt_seg.s_no = lpFrag->getBeginPckNo();
                    stt_seg.s_b_tm = lpFrag->getBeginTime();
                    stt_seg.s_e_tm = lpFrag->getEndTime();
                    stt_seg.s_pck_MTU += lpFrag->get_pck_MTU();
                    stt_seg.s_pck_MTU_PSH += lpFrag->get_pck_MTU_PSH();
                    stt_seg.s_TLS_flag += lpFrag->get_TLS_flag();
                    if(stt_seg.s_max_flen < lpFrag->getFragmentLen())
                        stt_seg.s_max_flen = lpFrag->getFragmentLen();
                    if(stt_seg.s_min_flen > lpFrag->getFragmentLen())
                        stt_seg.s_min_flen = lpFrag->getFragmentLen();
                    if(lpFrag->getFragmentLen() > len_header)
                        stt_seg.lp_vct_frag->push_back(lpFrag->getFragmentLen() - len_header);
                }
            }
            else if(ifrag == 2)
            {
                if(lpFrag->getTLSType()==23 && lpFrag->isClient())
                    int wos = 1;
                if(lpFrag->getTLSType()==23 && lpFrag->isClient() && lpFrag->getFragmentLen()>MIN_REQUEST)
                {   //fragmentation message
                    stt_seg.s_pk_end = lpFrag->get_s_pkn();

                    saveStatSegment(fp, &stt_seg);

                    ifrag = 1;
                    init_segment(&stt_seg);
                    stt_seg.c_fragment = 1;
                    stt_seg.c_length = lpFrag->getFragmentLen();
                    stt_seg.c_no = lpFrag->getBeginPckNo();
                    //stt_seg.c_port = cport;
                    stt_seg.c_time = lpFrag->getBeginTime();
                    stt_seg.s_pk_begin = lpFrag->get_s_pkn();
                }
                else if(lpFrag->getTLSType()==23 && !lpFrag->isClient())
                {
                    stt_seg.s_length += lpFrag->getFragmentLen();
                    if(lpFrag->getFragmentLen()>len_header)
                    {
                        stt_seg.s_estimate += lpFrag->getFragmentLen() - len_header;
                        stt_seg.s_estimate2 += lpFrag->getFragmentLen() - len_header;
                    }
                    stt_seg.s_fragment ++;
                    stt_seg.s_e_tm = lpFrag->getEndTime();
                    stt_seg.s_pck_MTU += lpFrag->get_pck_MTU();
                    stt_seg.s_pck_MTU_PSH += lpFrag->get_pck_MTU_PSH();
                    stt_seg.s_TLS_flag += lpFrag->get_TLS_flag();
                    if(stt_seg.s_max_flen < lpFrag->getFragmentLen())
                        stt_seg.s_max_flen = lpFrag->getFragmentLen();
                    if(stt_seg.s_min_flen > lpFrag->getFragmentLen())
                        stt_seg.s_min_flen = lpFrag->getFragmentLen();
                    if(lpFrag->getFragmentLen() > len_header)
                        stt_seg.lp_vct_frag->push_back(lpFrag->getFragmentLen() - len_header);
                }
            }
        }
    }
    if(ifrag == 2)
    {
        stt_seg.s_pk_end = cntSPck;
        saveStatSegment(fp, &stt_seg);
    }
}

void TLS_flow::init_segment(stt_ADU_TLS *lp_seg)
{
    lp_seg->str_pcap = lpCreator->get_pcap();
    lp_seg->c_fragment = 0;
    lp_seg->c_length = 0;
    lp_seg->c_no = 0;
    //lp_seg->c_port = 0;
    lp_seg->c_time = 0;
    lp_seg->s_min_flen = UINT16_MAX;
    lp_seg->s_max_flen = 0;
    lp_seg->s_pk_begin = 0;

    lp_seg->lp_vct_frag = new vector<uint32_t>;
}

void TLS_flow::saveStatSegment(FILE* fp, stt_ADU_TLS* lpSeg)
{
    if(fp)
    {
        fprintf(fp, "%d,%.4f,%d,%.4f,%.4f,%u,,%d,%d,,%d,%d,%d,%d,%d,%d,,",
                lpSeg->c_no, lpSeg->c_time, lpSeg->s_no, lpSeg->s_b_tm, lpSeg->s_e_tm,
                lpSeg->s_pk_end-lpSeg->s_pk_begin, 
                lpSeg->c_fragment, lpSeg->c_length, 
                lpSeg->s_fragment, lpSeg->s_length,
                lpSeg->s_first_frag, lpSeg->s_max_flen, lpSeg->s_min_flen, 
                lpSeg->s_estimate);
        fprintf(fp, "\n");
                
        lpCreator->add_ADU(strServer, *lpSeg);
    }
}

int TLS_flow::search_TLS_flag(CPacket* lppck)
{
    int len, iout = -1;
    uint8_t *buffer = lppck->getPacketPayload(len);

    for(int i=0; i<len-2; i++)
    {
        if(buffer[i] == 0x17 && buffer[i+1] == 3 && buffer[i+2] == 3)
            iout = i;
    }
    return iout;
}

void TLS_flow::setBaseSeq_off(CPacket* lppck, bool bClient, int off)
{
    if(!bBaseSequence)
    {
        if(bClient)
        {
            baseSeq_c = lppck->getSelfSeq();
            baseSeq_s = lppck->getAckSeq() + off;
        }
        else
        {
            baseSeq_s = lppck->getSelfSeq() + off;
            baseSeq_c = lppck->getAckSeq();
        }
        bBaseSequence = true;
    }
}

void TLS_flow::setBaseSeq(CPacket* lppck, bool bClient)
{
    if(!bBaseSequence)
    {
        if(bClient)
        {
            baseSeq_c = lppck->getSelfSeq();
            baseSeq_s = lppck->getAckSeq();
        }
        else
        {
            baseSeq_s = lppck->getSelfSeq();
            baseSeq_c = lppck->getAckSeq();
        }
        bBaseSequence = true;
    }
}

int TLS_flow::calSeq(uint32_t seq, uint32_t base)
{
    int uiout;

    if(seq>base)
        uiout = seq - base;
    else if(seq < base && seq > base - 1024*1024)
        uiout = seq - base;
    else if(seq < base-50000000)
        uiout = (unsigned int)(0xffffffff-base+seq+1);
    else
        uiout = 0;
    return uiout;
}

void TLS_flow::calPckSeq(uint32_t seq_c, uint32_t seq_s, int& retSeq_c, int& retSeq_s)
{
    retSeq_c = calSeq(seq_c, baseSeq_c);
    retSeq_s = calSeq(seq_s, baseSeq_s);
}

int TLS_flow::checkTLSContent(CPacket* lppck)
{
    int iout = 0;
    int len;
    unsigned char *buffer = lppck->getPacketPayload(len);

    if(len>22 && buffer[0]>=20 && buffer[0]<=24 && buffer[1]==3)
    {
        uint16_t len = buffer[3]*256+buffer[4];
        if(len<16*1024+100)
        {
            iout = buffer[0];
        }
    }
    return iout;
}

bool TLS_flow::isTLSClienthello(unsigned char *buffer, int len)
{
    bool bout = false;
    if(buffer[0]==0x16 && buffer[1]==3 && buffer[5]==1 && len>100)
        bout = true;
    return bout;
}

bool TLS_flow::isTLSServerhello(unsigned char *buffer, int len)
{
    bool bout = false;
    if(buffer[0]==0x16 && buffer[1]==3 && buffer[5]==2 && len>50)
        bout = true;
    return bout;
}

bool TLS_flow::isTLSApplicationData(unsigned char *buffer, int len)
{
    bool bout = false;
    if(buffer[0]==0x17 && buffer[1]==3 && buffer[2]==3 && len>5)
        bout = true;
    return bout;

}

bool TLS_flow::isTLSFormat(unsigned char *buffer, int len)
{
    bool bout = false;
    if( (buffer[0]>=0x14 && buffer[0]<=0x17) &&
        buffer[1]==3 && 
        (buffer[2]>=2 && buffer[2]<=4) && 
        len>5)
    {
        uint16_t len;
        unsigned char p1[3];
        p1[0] = buffer[4];
        p1[1] = buffer[3];
        memcpy(&len, p1, sizeof(uint16_t));
        if(len>0 && len<1024*16+40)
            bout = true;
    }
    return bout;
}

void TLS_flow::checkFragmentRecover(ITLSFragmentation* lpFR, 
                                    std::vector<TLS_fragment*> *lpVct, 
                                    double time, int pckno, 
                                    bool bSou, uint32_t s_pk, uint32_t s_seq,
                                    bool new_tls_pck)
{
    int lenFragment;
    TLS_fragment* ctf;
    uint8_t c_type, f_type;
    int next_len;

    if(lpVct && lpFR){
        lenFragment = lpFR->getTLSFragment_from_buffer(c_type, f_type);
        while(lenFragment>0){
            ctf = new TLS_fragment(time, pckno, lenFragment, c_type, bSou, new_tls_pck);
            if(new_tls_pck)
                new_tls_pck = false;
            ctf->setServerMsg(s_pk, s_seq);
            lpVct->push_back(ctf);
            if(bSou)
                cur_c_fragment = ctf;
            else
                cur_s_fragment = ctf;
            lenFragment = lpFR->getTLSFragment_from_buffer(c_type, f_type);
        }
    }
}

void TLS_flow::getServerInfo(CPacket* lppck, bool bSD)
{
    if(lppck->getIPVer()==4)
    {
        IPver = 4;
        if(bSD)
            sIPv4 = lppck->getSrcIP4();
        else
            sIPv4 = lppck->getDstIP4();
    }
    else
    {
        IPver = 6;
        if(bSD)
            memcpy(sIPv6, lppck->getSrcIP6(), CPacket::lenIPV6);
        else
            memcpy(sIPv6, lppck->getDstIP6(), CPacket::lenIPV6);
    }
    if(bSD)
    {
        sport = lppck->getSrcPort();
        cport = lppck->getDstPort();
    }
    else
    {
        sport = lppck->getDstPort();
        cport = lppck->getSrcPort();
    }

}

int TLS_flow::sub_string(char* sub, uint8_t* buf, int sub_len, int len)
{
    int iout = -1;
    int i,j;

    for(i=0; i<=len-sub_len; i++){
        if(buf[i] == sub[0])
        {
            bool beq = true;
            for(j=1; j<sub_len; j++)
            {
                if(buf[i+j] != sub[j])
                {
                    beq = false;
                    break;
                }
            }
            if(beq)
            {
                iout = i;
                break;
            }
        }
    }
    return iout;
}

//==============================================================================
//==============================================================================
//==============================================================================

void SNI_segment::save_segment(FILE* fp)
{
    if(fp)
    {
        fprintf(fp, "SNI,%s\n", str_SNI.c_str());
        fprintf(fp, "file,c_no,c_len,s_len,s_esti,s_esti_nohead\n");
        for(vector<stt_ADU_TLS>::iterator iter=vct_ADU.begin(); iter!=vct_ADU.end(); ++iter)
        {
            fprintf(fp, "%s,%d,%d,%d,%d,", (*iter).str_pcap.c_str(), (*iter).c_no,
                        (*iter).c_length, (*iter).s_length, (*iter).s_estimate);
            if((*iter).i_flag==0)
                fprintf(fp, "%d", (*iter).s_estimate2);
            fprintf(fp, ",,");
            for(vector<uint32_t>::iterator iter_len=(*iter).lp_vct_frag->begin(); iter_len!=(*iter).lp_vct_frag->end(); ++iter_len)
                fprintf(fp, "%d,", (*iter_len));
            fprintf(fp, "\n");
        }
    }
}

path_data::~path_data()
{
    for(vector<SNI_segment*>::iterator iter=vct_SNI.begin(); iter!=vct_SNI.end(); ++iter)
    {
        if(*iter)
            delete(*iter);
    }
}

void path_data::add_segment(std::string sni, stt_ADU_TLS st_ADU)
{
    if(!sni.empty() && sni != "N/A")
    {
        bool bfind = false;
        for(vector<SNI_segment*>::iterator iter=vct_SNI.begin(); iter!=vct_SNI.end(); ++iter)
        {
            if(*iter)
            {
                if((*iter)->get_SNI() == sni)
                {
                    (*iter)->add_segment(st_ADU);
                    bfind = true;
                }
            }
        }
        if(!bfind)
        {
            SNI_segment* lp_sni = new SNI_segment(sni);
            lp_sni->add_segment(st_ADU);
            vct_SNI.push_back(lp_sni);
        }
    }
}
