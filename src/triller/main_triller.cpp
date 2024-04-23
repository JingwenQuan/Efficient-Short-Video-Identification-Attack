/**
 * @file main_triller.cpp (src/triller/main_triller.cpp)
 * @author jwquan(jwquan@seu.edu.cn) hwu(hwu@seu.edu.cn) jjdu(jjdu@seu.edu.cn) xyhu(xyhu@njnet.edu.cn)
 * @brief source code for our paper Efficient Short Video Identification Attack in Hybrid Transmission Modes with Preloading Mechanism Scenario
 * @version 0.1
 * @date 2024-4-18
 */

#include <iostream>
#include <cstring>
#include <time.h>
#include <bits/stdc++.h>

#include "_lib.h/libconfig.h++"
#include "_lib.h/libPcapSE.h"
#include "winlin/winlinux.h"

#include "triller/triller_flow.h"

using namespace std;  
using namespace libconfig;

int main(int argc, char *argv[])
{
    char buf[UINT8_MAX] = "data.cfg";

    if(argc==2)
        strcpy(buf, argv[1]);

    std::cerr << "SVI begin" << std::endl;        

    Config cfg;
    try
    {
        cfg.readFile(buf);
    }
    catch(...)
    {
        std::cerr << "I/O error while reading file." << std::endl;
        return(EXIT_FAILURE);
    }    

    try
    {
        string path = cfg.lookup("triller_pcap_Path");    
        cout << "path name: " << path << endl;
        string str_fp = cfg.lookup("triller_fp");    
        cout << "fingerprint file name: " << str_fp << endl;
        string str_fill = "triller";    
        string str_fp2 = cfg.lookup("triller_fp2");    
        cout << "fp2 file name: " << str_fp2 << endl;
        int thre = 1000;

        fp_file *lp_fp = new fp_file();
        if(lp_fp->loadfile(str_fp.c_str()))
        {
            if(str_fp2.length() > 0)
                lp_fp->load_fp2(str_fp2.c_str());

            if(path.length()>0)
            {
                vector<string> vctFN;
                if(iterPathPcaps(path, &vctFN))
                {
                    path_data *lp_PD = new path_data();

                    for(vector<string>::iterator iter=vctFN.begin(); iter!=vctFN.end(); ++iter)
                    {
                        string strFN = *iter;
                        cout << "pcap file:" << strFN << endl;

                        packet_statistics_object_type typeS = pso_IPPortPair;
                        IFlow2Stat* lpFS = CFlow2StatCreator::create_flow2_stat(strFN, 25, 1, 0);
                        triller_flow_creator* lpFC = new triller_flow_creator(typeS, strFN, str_fill, thre, 0);
                        if(lpFS && lpFC)
                        {
                            lpFS->setParameter(typeS, 1, psm_SouDstDouble, true);
                            lpFS->setCreator(lpFC);
                            lpFC->set_path_data(lp_PD);
                            if(lpFS->isChecked())
                            {
                                lpFS->iterPcap();
                                lpFC->save_ADU_sorted();
                                lpFC->save_sorted_triller(strFN, lp_fp);
                            }
                            delete lpFC;
                            delete lpFS;
                        }
                        else
                            cout << "pcap file " << strFN << " open error!" << endl;
                    }

                }
            }
        }
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        return(EXIT_FAILURE);
    }

    return 0;
}