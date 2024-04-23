#ifndef H1H2_FLOW_H
#define H1H2_FLOW_H

#include "_lib.h/libFlow2SE.h"
#include "_lib.h/libTlsFragSE.h"
#include "fingerprint/smp_fp.h"
#include <vector>

struct stt_ADU_TLS
{
    std::string str_pcap;

    double c_time;
    int c_no;
    double s_b_tm;
    double s_e_tm;
    int s_no;

    int c_fragment;
    int c_length;
    int s_fragment;
    int s_length;
    int s_first_frag;
    int s_max_flen;
    int s_min_flen;
    int s_estimate;
    int s_estimate2;
    int i_flag;    
    int s_pk_begin;
    int s_pk_end;
    int s_pck_MTU;
    int s_pck_MTU_PSH;
    int s_TLS_flag;

    std::vector<uint32_t> *lp_vct_frag;
    std::vector<stt_segment> vct_match;
    stt_segment st_seg;
};

class SNI_segment
{
public:
    SNI_segment(std::string str_sni) {str_SNI = str_sni;}
    ~SNI_segment() {vct_ADU.clear();}
public:
    std::string get_SNI() {return str_SNI;}
    void add_segment(stt_ADU_TLS st_ADU) {vct_ADU.push_back(st_ADU);}
    void save_segment(FILE* fp);
protected:
    std::string str_SNI;
    std::vector<stt_ADU_TLS> vct_ADU;
};

class path_data
{
public:
    ~path_data();
public:
    void add_segment(std::string sni, stt_ADU_TLS st_ADU);
protected:
    std::vector<SNI_segment*> vct_SNI;
};

class TLS_fragment
{
public:
    TLS_fragment(double tm, int pck, int len, uint8_t uc, bool sou, bool ntp)
    {
        dbBT = dbET = tm;
        pckBNo = pckENo = pck;
        lenFragment = len;
        uChar = uc;
        bSou = sou;
        pck_MTU = pck_MTU_PSH = 0;
        if(ntp)
            pck_TLS_flag = 1;
        else
            pck_TLS_flag = 0;
    }
public:
    double getBeginTime()       {return dbBT;}
    double getEndTime()         {return dbET;}
    uint32_t getBeginPckNo()    {return pckBNo;}
    uint32_t getEndPckNo()      {return pckENo;}
    int getFragmentLen()        {return lenFragment;}
    uint8_t getTLSType()        {return uChar;}
    bool isClient()             {return bSou;}
    uint32_t get_s_pkn()        {return s_pkn;}
    uint32_t get_s_seq()        {return s_seq;}
    void add_MTU_pck()          {pck_MTU++;}
    void add_MTU_PSH()          {pck_MTU_PSH++;}
    int get_pck_MTU()           {return pck_MTU;}
    int get_pck_MTU_PSH()       {return pck_MTU_PSH;}
    int get_TLS_flag()          {return pck_TLS_flag;}
public:
    void setLastPacket(double dbt, uint32_t pkn) {dbET = dbt; pckENo = pkn;}
    void setServerMsg(uint32_t pk, uint32_t seq) {s_pkn = pk; s_seq = seq;}
private:
    double dbBT, dbET;
    uint32_t pckBNo, pckENo;
    uint32_t s_pkn, s_seq;
    int lenFragment;
    uint8_t uChar;
    bool bSou;
private:
    int pck_MTU, pck_MTU_PSH, pck_TLS_flag;
};

//==============================================================================
//==============================================================================
//==============================================================================

class TLS_flow_creator: public IFlow2ObjectCreator
{
public:
    TLS_flow_creator(packet_statistics_object_type type, std::string fname, 
                      std::string filter, int thre, int header);
    ~TLS_flow_creator();
public:
    IFlow2Object* create_Object(uint8_t* buf, int len);
public:    
    packet_statistics_object_type getStatType() {return pso_type;}
    bool isSave() {return true;}

    std::string getName() {return str_tls;}
    std::string getStat() {return str_seg;}
    std::string get_filter() {return str_filter;}
    std::string get_pcap() {return str_pcap;}
    int get_TLS_thre() {return tls_pck_thre;}
    int get_TLS3_header_len() {return tls3_header;}
    void set_path_data(path_data *lp_pd) {lp_path_data = lp_pd;}
public:
    void add_ADU(std::string str_sni, stt_ADU_TLS st_ADU);
    bool save_ADU_sorted();
protected:
    std::vector<stt_ADU_TLS> vct_ADU;
private:
    bool open_csv(std::string str_name);
private:
    packet_statistics_object_type pso_type;
    std::string str_pcap, str_tls, str_seg, str_sort;
    int tls_pck_thre, tls3_header;
    std::string str_filter;
private:
    path_data *lp_path_data;
};

//==============================================================================
//==============================================================================
//==============================================================================

class TLS_flow: public IFlow2Object
{
public:
    TLS_flow(uint8_t* buf, int len, TLS_flow_creator* lpFOC);
    ~TLS_flow();
public:
    bool addPacket(CPacket* lppck, bool bSou);
    bool saveObject(FILE* fp, uint64_t cntP, bool bFin);
public:
    bool checkObject()
    {
        if(lenKey>0 && bufKey)
            return true;
        else
            return false;
    }

    bool isSameObject(uint8_t* buf, int len)
    {
        bool bout = false;
        if(lenKey == len)
        {
            if(memcmp(bufKey, buf, len)==0)
                bout = true;
        }
        return bout;
    }

    uint32_t getPckCnt() {return cntPck;}
    void incPckCnt() {cntPck++;}
private:
    uint32_t cntPck;
    uint32_t cntSPck;
private:
    TLS_flow_creator* lpCreator;
    uint8_t* bufKey;
    int lenKey;
private:
    bool bTLS;
    bool b_http_web;
    bool bErrorData;
private:        //TLS info
    std::string strServer;

    uint32_t sIPv4;
    uint8_t sIPv6[16];
    uint16_t sport;
    uint16_t cport;
    int IPver;
private:
    int MTU_value;
    char TLS_ID[6];
    int server_ID_cc;
private:        //SEQ
    uint32_t baseSeq_s;
    uint32_t baseSeq_c;
    bool bBaseSequence;

    void setBaseSeq(CPacket* lppck, bool bClient);
    void setBaseSeq_off(CPacket* lppck, bool bClient, int off);
    void calPckSeq(uint32_t seq_a, uint32_t seq_b, int& iSeq_a, int& iSeq_b);
    int calSeq(uint32_t seq, uint32_t base);
private:        //TLS fragmatation
    ITLSFragmentation *TLS_FR_s;
    ITLSFragmentation *TLS_FR_c;
    int tls_ver;
    std::vector<TLS_fragment*> vctTLSFragments;
    TLS_fragment *cur_c_fragment, *cur_s_fragment;

    void checkFragmentRecover(ITLSFragmentation* lpFR, 
                              std::vector<TLS_fragment*> *lpVct, 
                              double time, int pckno, 
                              bool bSou, uint32_t s_pk, uint32_t s_seq,
                              bool new_tls_pck);
private:
    int checkTLSContent(CPacket* lppck);
    void saveStat(FILE* fp);
    void saveStatSegment(FILE* fp, stt_ADU_TLS* lpSeg);
private:
    bool isTLSClienthello(unsigned char *buffer, int len);
    bool isTLSServerhello(unsigned char *buffer, int len);
    bool isTLSApplicationData(unsigned char *buffer, int len);
    bool isTLSFormat(unsigned char *buffer, int len);
    int search_TLS_flag(CPacket* lppck);

    void getServerInfo(CPacket* lppck, bool bSD);
    int sub_string(char* str, uint8_t* pbuf, int len, int strlen);

    void init_segment(stt_ADU_TLS *lp_seg);
};


#endif