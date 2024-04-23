#ifndef SMP_FP_H
#define SMP_FP_H

#include <vector>
#include <string>
#include <stdint.h>

struct stt_video_reso
{
    std::string reso_info;
    uint16_t reso_ID;
};

struct stt_video
{
    std::string video_name;
    uint32_t video_ID;
    std::vector<stt_video_reso> vct_resolution;
};

struct stt_fp2
{
    std::string vname;
    uint32_t length;
};

struct stt_segment
{
    uint32_t video_ID;
    uint16_t reso_ID;
    uint16_t seg_idx;
    uint32_t len_seg;
    uint32_t len_TLS_payload;
    uint32_t len_min;
    uint32_t len_max;
};

struct stt_seg_video
{
    uint32_t video_ID;
    double tm_b;
    double tm_e;
    int len_data;
    int num_seg;
};

class video_fp
{
public:
    video_fp(std::string id, std::string reso, int seg);
    ~video_fp();
public: 
    void add_segment(uint32_t len){vctSegLen.push_back(len);}
    bool check_video(){return vctSegLen.size()==cntSeg;}
public:
    std::string get_video_ID() {return str_ID;}
    std::string get_video_reso() {return str_reso;}
    std::string get_message() {return str_ID + "_" + str_reso;}
    std::vector<uint32_t>* get_segments() {return &vctSegLen;}
    int get_seg_num() {return vctSegLen.size();}
    void clear_segment() {vctSegLen.clear();}
private:    
    std::string str_ID;
    std::string str_reso;
    int cntSeg;
    std::vector<uint32_t> vctSegLen;
};

class fp_file
{
public: 
    fp_file();
    ~fp_file();
public:
    bool loadfile(const char* fname, int type=1);
    bool load_fp2(const char* fname);
    void match_segment(int len, std::vector<stt_segment> *lp_seg);
    bool match_fp2(int len, char *buffer, char *msg, char *msg2);
    bool get_video_info(char *lp_buf, uint32_t vid, uint16_t reso);
    bool get_video_info(char *lp_buf, uint32_t vid);
    void check_same_fp();
    bool save_fp(const char* fname);
private:
    std::vector<stt_video> vct_video;
    std::vector<stt_segment> vct_segment;
    std::vector<stt_fp2> vct_fp2;
private:
    std::string str_fp;
    std::vector<video_fp*> vct_VFP;
private:
    bool read_line(FILE* fp, char* buf);
    video_fp* getVideoFromLine(char* buffer);

    void make_fp(video_fp* lp_vfp);
    bool get_video_reso(std::string vid, std::string reso, stt_segment *lp_seg);

    bool comp_same(video_fp *lp_fp1, video_fp *lp_fp2);
};

#endif