#ifndef TOOL_TLS_H
#define TOOL_TLS_H

#include <stdint.h>
#include <_lib.h/libPacketSE.h>

static inline bool check_TLS_clienthello(uint8_t *lp_buf, int len)
{
    if(len > 100 && 
            lp_buf[0]==0x16 && lp_buf[1]==3 && (lp_buf[2]==1 || lp_buf[2]==3) && 
            lp_buf[5]==1)
        return true;
    else
        return false;
}

static inline bool check_TLS_serverhello(uint8_t *lp_buf, int len)
{
    if(len > 50 && lp_buf[0]==0x16 && lp_buf[1]==3 && lp_buf[2]==3 && lp_buf[5]==2)
        return true;
    else
        return false;
}

static inline uint8_t check_TLS_header(uint8_t *lp_buf, int len_buf, int& len_record)
{
    uint8_t uout = 0;

    if(len_buf > 5)
    {
        if(lp_buf[0] == 0x14 || lp_buf[0] == 0x15 || lp_buf[0] == 0x16 || lp_buf[0] == 0x17 || lp_buf[0] == 0xff)
        {
            if(lp_buf[1] == 3 && (lp_buf[2]==3 || (lp_buf[0]==0x16 && lp_buf[2]==1)))    
            {
                len_record = lp_buf[3] * 256 + lp_buf[4];
                if(len_record < 16500)
                    uout = lp_buf[0];
            }
        }
    }
    return uout;
}

static inline bool get_CH_ex_SNI(uint8_t *lp_buf, int len_buf, char* lp_sni)
{
    bool bout = false;

    int pos, newpos;
    int type, len_para, len_ext;
//    char buf_str[UINT8_MAX];
    if(len_buf > 38+1)    //CH 1 + length 3 + version 2 + random 32 = 38
    {
        pos = 38;
        len_para = lp_buf[pos];                              // session id 1B

        newpos = pos+1+len_para;
        if(len_para >= 0 && len_buf > newpos+2 )
        {
            pos = newpos;
            len_para = lp_buf[pos]*256+lp_buf[pos+1];    //cipher suites 2B

            newpos = pos+2+len_para;
            if(len_para > 0 && len_buf > newpos+1)
            {
                pos = newpos;
                len_para = lp_buf[pos];                      //compression method
                newpos = pos+1+len_para;
                if(len_para > 0 && len_buf > newpos+2)
                {
                    pos = newpos;
                    len_ext = lp_buf[pos]*256 + lp_buf[pos+1];    //extensions

                    if(len_ext >= 0 && len_buf >= pos+4 )
                    {
                        pos = newpos + 2;

                        while(pos+4 < len_buf)
                        {
                            type = lp_buf[pos]*256+lp_buf[pos+1];
                            if(type==0 && len_buf > pos+8)             //server
                            {  
                                //CServerName 2 + len 2 + sn list len 2 + host_name(0) 1
                                if(lp_buf[pos+6]==0)    //host_name
                                {
                                    int len_sni = lp_buf[pos+7]*256+lp_buf[pos+8];
                                    //cout << "sni len:" << lenExt << endl;
                                    if(len_sni>0  && len_sni<UINT8_MAX && pos+9+len_sni <= len_buf){
                                        memcpy(lp_sni, lp_buf+pos+9, len_sni);
                                        lp_sni[len_sni] = 0;

                                        bout = true;
                                    }
                                }
                                break;
                            }
                            len_para = 4 + lp_buf[pos+2]*256+lp_buf[pos+3]; // type + lenbuf + data
                            pos += len_para;
                        }
                    }
                }
            }
        }
    }

    return bout;
}

static inline int get_CH_SNI(uint8_t *lp_payload, int len_pl, char *lp_sni)
{
    int iout = 0;

    int pos, newpos;
    int lenPara, len_TLS_CH;

    if(len_pl>100 && 
        lp_payload[0]==0x16 && lp_payload[1]==3 && (lp_payload[2]==1 || lp_payload[2]==3) && 
        lp_payload[5]==1)
    {
        len_TLS_CH = lp_payload[3]*256+lp_payload[4];
        //cout << "CH len:" << lenCH << "," << len << endl;
        if(len_TLS_CH + 5 > len_pl)  //CH in two packets;
        {
            iout = 2;
            len_TLS_CH = len_pl - 5;
        }
        
        bool ret = get_CH_ex_SNI(lp_payload + 5, len_TLS_CH, lp_sni);
        if(ret)
            iout = 1;
    }
    return iout;    
}

class detect_TLS_CH
{
public:
    detect_TLS_CH(std::string filter) {
        str_filter = filter;
        buf_ch = NULL;
    }
    ~detect_TLS_CH() {
        if(buf_ch)
            free(buf_ch);
    }
public:
    //first packet
    int set_CH_first_pck(CPacket* lppck){
        int iout = 3;
        //first seq
        uint32_t base_seq = lppck->getSelfSeq();
        //first buf
        int len;
        uint8_t *buf;
        buf = lppck->getPacketPayload(len);
        //
        char lp_SNI[UINT8_MAX];
        int type_ch = get_CH_SNI(buf, len, lp_SNI);
        if(type_ch==1)
            iout = check_SNI(lp_SNI);
        else if(type_ch == 2){
            seq_next = base_seq + len;
            len_CH = buf[3]*256+buf[4] + 5;
            pos_next = len;
            //copy buffer
            if(len_CH < 16500){
                buf_ch = (uint8_t *)malloc(len_CH);
                if(buf_ch){
                    memcpy(buf_ch, buf, len);
                    iout = 1;
                }else
                    iout = 3;
            }else
                iout = 3;
        }else
            iout = 3;
        return iout;
    }
    //next packet
    int set_CH_next_pck(CPacket* lppck){
        int iout = 0;
        //next seq
        uint32_t seq = lppck->getSelfSeq();
        //
        if(seq == seq_next){
            int len;
            uint8_t *buf;
            char lp_SNI[UINT8_MAX];
            buf = lppck->getPacketPayload(len);
            if(len >= len_CH - pos_next){
                if(buf_ch){
                    memcpy(buf_ch + pos_next, buf, len_CH - pos_next); 
                    int type_ch = get_CH_SNI(buf_ch, len_CH, lp_SNI);
                    if(type_ch == 1)
                        iout = check_SNI(lp_SNI);
                    else
                        iout = 3;
                }else
                    iout = 3;
            }else
                iout = 3;
        }else if(seq > seq_next)
            iout = 3;
        else
            iout = 1;
        return iout;
    }
    std::string get_SNI(){
        return str_SNI;
    }
private:
    uint8_t* buf_ch;
    std::string str_filter, str_SNI;
    uint32_t seq_next;
    int len_CH, pos_next;
private:
    int check_SNI(char* lp_buf){
        int iout = 0;
        if(str_filter.empty() || (!str_filter.empty() &&
                strstr(lp_buf, str_filter.c_str()))){
            str_SNI = lp_buf;
            iout = 2;
        }else
            iout = 3;
        return iout;
    }
};

/**
 * @brief 在2packet CH中找SNI，如果找到提出来，如果没找到，算出下一个extern的offset
 * @param uint8_t *lp_buf buffer指针
 * @param int len_buf buffer长度
 * @param char* lp_sni 传出的sni
 * @param uint16_t &off_next 传出的offset
 * 
*/
static inline int get_CH_ex_SNI_multi_pck(uint8_t *lp_buf, int len_buf, char* lp_sni, uint16_t &off_next)
{
    int iout = 0;

    int pos, newpos;
    int type, len_para, len_ext;
//    char buf_str[UINT8_MAX];
    if(len_buf > 38+1)    //CH 1 + length 3 + version 2 + random 32 = 38
    {
        pos = 38;
        len_para = lp_buf[pos];                              // session id 1B

        newpos = pos+1+len_para;
        if(len_para >= 0 && len_buf > newpos+2 )
        {
            pos = newpos;
            len_para = lp_buf[pos]*256+lp_buf[pos+1];    //cipher suites 2B

            newpos = pos+2+len_para;
            if(len_para > 0 && len_buf > newpos+1)
            {
                pos = newpos;
                len_para = lp_buf[pos];                      //compression method
                newpos = pos+1+len_para;
                if(len_para > 0 && len_buf > newpos+2)
                {
                    pos = newpos;
                    len_ext = lp_buf[pos]*256 + lp_buf[pos+1];    //extensions

                    if(len_ext >= 0 && len_buf >= pos+4 )
                    {
                        pos = newpos + 2;

                        while(pos+4 < len_buf)
                        {
                            type = lp_buf[pos]*256+lp_buf[pos+1];
                            if(type==0 && len_buf > pos+8)             //server
                            {  
                                //CServerName 2 + len 2 + sn list len 2 + host_name(0) 1
                                if(lp_buf[pos+6]==0)    //host_name
                                {
                                    int len_sni = lp_buf[pos+7]*256+lp_buf[pos+8];
                                    //cout << "sni len:" << lenExt << endl;
                                    if(len_sni>0  && len_sni<UINT8_MAX && pos+9+len_sni <= len_buf){
                                        memcpy(lp_sni, lp_buf+pos+9, len_sni);
                                        lp_sni[len_sni] = 0;

                                        iout = 1;
                                    }
                                }
                                break;
                            }
                            len_para = 4 + lp_buf[pos+2]*256+lp_buf[pos+3]; // type + lenbuf + data
                            if(pos + len_para > len_buf)
                            {
                                off_next = pos + len_para - len_buf;
                                iout = 2;
                                break;
                            }
                            pos += len_para;
                        }
                    }
                }
            }
        }
    }
    return iout;
}

static inline int get_CH_SNI_next_pck(uint8_t *lp_payload, int len_payload, char *lp_sni, 
                                        uint16_t off_next, uint16_t len_left)
{
    int iout = 0;
    int pos = off_next, length, type, len_para;
    if(len_payload > len_left)
        length = len_left;
    else
        length = len_payload;

    while(pos+4 < length)
    {
        type = lp_payload[pos]*256+lp_payload[pos+1];
        if(type==0 && length > pos+8)             //server
        {  
            //CServerName 2 + len 2 + sn list len 2 + host_name(0) 1
            if(lp_payload[pos+6]==0)    //host_name
            {
                int len_sni = lp_payload[pos+7]*256+lp_payload[pos+8];
                //cout << "sni len:" << lenExt << endl;
                if(len_sni>0  && len_sni<UINT8_MAX && pos+9+len_sni <= length){
                    memcpy(lp_sni, lp_payload+pos+9, len_sni);
                    lp_sni[len_sni] = 0;
                    iout = 1;
                }
            }
            break;
        }
        len_para = 4 + lp_payload[pos+2]*256+lp_payload[pos+3]; // type + lenbuf + data
        pos += len_para;
    }
    return iout;
}

/**
 * @brief 从CH第一个packet里找SNI
 * @param uint8_t *lp_payload   payload buffer 
 * @param int len_pl            length of payload
 * @param char *lp_sni          sni buffer
 * @param uint16_t &off_next    next extensions offset in next packet
 * @param uint16_t &len_CN      length of CH
 * @return int 1 --- find SNI, 0 --- perhaps in next packet
*/
static inline int get_CH_SNI_first_pck(uint8_t *lp_payload, int len_pl, char *lp_sni, uint16_t &off_next, uint16_t &len_CH)
{
    int iout = 0;
    int len_TLS_CH;
    bool ret;

    if(len_pl>100 && 
        lp_payload[0]==0x16 && lp_payload[1]==3 && (lp_payload[2]==1 || lp_payload[2]==3) && 
        lp_payload[5]==1)
    {
        len_TLS_CH = lp_payload[3]*256+lp_payload[4];
        if(len_TLS_CH + 5 > len_pl)  //CH in two packets;
        {
            len_CH = len_TLS_CH + 5;
            iout = get_CH_ex_SNI_multi_pck(lp_payload + 5, len_pl - 5, lp_sni, off_next);
        }else if(get_CH_ex_SNI(lp_payload + 5, len_TLS_CH, lp_sni))
            iout = 1;
    }
    return iout;    
}

#endif