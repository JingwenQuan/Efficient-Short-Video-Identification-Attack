/**
 * @file libTlsFrag.h (https://www.seu.edu.cn/) 
 * @author cayman.Hu (caymanhu@qq.com)
 * @brief TLS 分块处理
 * @version 0.1
 * @date 2021-10-22
 */
#ifndef LIB_TLS_FRAG_SE_H
#define LIB_TLS_FRAG_SE_H

#include <cstdlib>
#include <cstring>
#include <stdint.h> 
#include <vector>

struct stt_TLS_fragment
{
    uint32_t seq_begin;
    uint32_t seq_end;
    uint16_t len_TLS;
    uint8_t content_type;
    uint8_t restoration_type;
};

class ITLSFragmentation
{
public:
    virtual ~ITLSFragmentation() {}
public: //check
    /**
     * @brief 检查packet payload的前5个字节，是否是TLS块标志。
     * 
     * @param buf packet payload
     * @param len length of packet payload
     * @return int TLS块method， 0--非TLS头部
     */
    virtual int checkTLSPck(uint8_t *buf, int len) = 0;

public: //buffer
    /**
     * @brief 确认TLS块后，分配内存
     * 
     * @return true， false 
     */
    virtual bool initBuffer() = 0;

    /**
     * @brief 清空并设置TLS块起始点
     * 
     * @param seq 起始点
     */
    virtual void initFragmentData(uint32_t seq) = 0;

    virtual int get_TLS_version() = 0;

    /**
     * @brief Set the Packet Payload into recover buffer
     * 
     * @param buf payload buffer
     * @param len payload length
     * @param seq sequence of payload begin
     * @param bLastPck the last packet of the previous TLS fragment
     * @return -1 --- error, insufficient memory, data loss
     */
    virtual int setPckPayload_into_buffer(uint8_t *buf, int len, uint32_t seq, bool &bLastPck) = 0;

public: //TLS fragmentation
    /**
     * @brief Get the TLS Fragment from recover buffer
     * 
     * @param content_type TLS fragment content type
     * @param fragment_type TLS fragment (get) type 
     *          1--one fragment in one packet 
     *          2--multiple fragments in one packet, lost packet
     *          3--get first packet of fragment
     *          4--libPcap not capture the first packet, the length is calculated from the offset of the next fragment
     * @return int --- the length of current TLS fragment, -1--error
     */
    virtual int getTLSFragment_from_buffer(uint8_t &content_type, uint8_t &fragment_type) = 0;

    virtual int get_vector_TLS_frament(std::vector<stt_TLS_fragment> *lp_TLSF) = 0;

    virtual int get_buffer_len() = 0;
};

/**
 * @brief 构造
 */
class CTLSFragCreator
{
public:
    static ITLSFragmentation* create_TLS_fragmentation(uint32_t size);
};


#endif
