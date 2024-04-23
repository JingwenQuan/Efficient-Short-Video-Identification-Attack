#ifndef FLOW2_TLS2_H
#define FLOW2_TLS2_H

#include "_lib.h/libFlow2SE.h"
#include "tool_TLS.h"

class flow2_TLS: public IFlow2Object
{
public:
    flow2_TLS(uint8_t* buf, int len){
        cntPck = 0;
        if(len>0)
        {
            lenKey = len;
            bufKey = (uint8_t*)calloc(lenKey, sizeof(uint8_t));
            if(bufKey)
                memcpy(bufKey, buf, len);
        }

        lp_detect_CH = NULL;
        i_TLS_state = 0;
        str_SNI = "";
    }
    ~flow2_TLS(){
        if(bufKey)
            free(bufKey);
        if(lp_detect_CH)
            delete lp_detect_CH;
    }
public:
public:
    bool checkObject(){
        if(lenKey>0 && bufKey)
            return true;
        else
            return false;
    }
    bool isSameObject(uint8_t* buf, int len){
        bool bout = false;
        if(lenKey == len)
        {
            if(memcmp(bufKey, buf, len)==0)
                bout = true;
        }
        return bout;
    }
public:
    uint32_t getPckCnt() {return cntPck;}
    void incPckCnt() {cntPck++;}
protected:
    uint8_t* bufKey;
    int lenKey;
protected:
    detect_TLS_CH* lp_detect_CH;
    int i_TLS_state;
    std::string str_SNI;
protected:
    virtual void create_TLS_stat(CPacket* lppck, bool bSrv) = 0;
    virtual bool check_SNI(std::string sni) {return false;}
protected:
    //标准过滤判断SNI
    void check_TLS_CH(CPacket* lppck, std::string str_filter){
        uint8_t *buf;
        if(cntPck < CH_threshold)
        {
            if(i_TLS_state == 0) //初始状态
            {
                int len_pl;
                buf = lppck->getPacketPayload(len_pl);
                if(check_TLS_clienthello(buf, len_pl))
                {
                    lp_detect_CH = new detect_TLS_CH(str_filter);
                    if(lp_detect_CH)
                    {
                        i_TLS_state = lp_detect_CH->set_CH_first_pck(lppck);
                        if(i_TLS_state == 1 || i_TLS_state == 2)
                        {
                            create_TLS_stat(lppck , false);
                            if(i_TLS_state == 2)
                                str_SNI = lp_detect_CH->get_SNI();
                        }
                    }
                    else
                        i_TLS_state = 3;
                }
                else    //client 第一个包不是CH
                    i_TLS_state = 3;
            }
            else if(i_TLS_state == 1) //CH in 2 packets
            {
                if(lp_detect_CH)
                {
                    i_TLS_state = lp_detect_CH->set_CH_next_pck(lppck);
                    if(i_TLS_state == 2)
                        str_SNI = lp_detect_CH->get_SNI();
                }
                else
                    i_TLS_state = 3;
            }
        }
        else    //超过阈值
            i_TLS_state = 3;
    }
    //子类check_SNI判断SNI
    void check_TLS_CH(CPacket* lppck){
        uint8_t *buf;
        if(cntPck < CH_threshold)
        {
            if(i_TLS_state == 0) //初始状态
            {
                int len_pl;
                buf = lppck->getPacketPayload(len_pl);
                if(check_TLS_clienthello(buf, len_pl))
                {
                    lp_detect_CH = new detect_TLS_CH("");
                    if(lp_detect_CH)
                    {
                        i_TLS_state = lp_detect_CH->set_CH_first_pck(lppck);
                        if(i_TLS_state == 1 || i_TLS_state == 2)
                        {
                            if(i_TLS_state == 2)
                            {
                                str_SNI = lp_detect_CH->get_SNI();
                                if(!check_SNI(str_SNI))
                                    i_TLS_state = 3;
                                else
                                    create_TLS_stat(lppck , false);
                            }
                            else
                                create_TLS_stat(lppck , false);
                        }
                    }
                    else
                        i_TLS_state = 3;
                }
                else    //client 第一个包不是CH
                    i_TLS_state = 3;
            }
            else if(i_TLS_state == 1) //CH in 2 packets
            {
                if(lp_detect_CH)
                {
                    i_TLS_state = lp_detect_CH->set_CH_next_pck(lppck);
                    if(i_TLS_state == 2)
                    {
                        str_SNI = lp_detect_CH->get_SNI();
                        if(!check_SNI(str_SNI))
                            i_TLS_state = 3;
                    }
                }
                else
                    i_TLS_state = 3;
            }
        }
        else    //超过阈值
            i_TLS_state = 3;
    }
private:
    uint32_t cntPck;
private:
    static const int CH_threshold = 10;    
};

#endif
