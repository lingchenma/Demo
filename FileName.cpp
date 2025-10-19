#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>

#include"FileName.h"
#ifdef __linux__
// linux 定义节方式 https://blog.csdn.net/nyist327/article/details/59481809 
using myown_call =  void (*)(void);
#define _init __attribute__((unused, section(".myown")))
#define func_init(func) myown_call _fn_##func _init = func
#elif _WIN32
// msvc section 使用介绍 https://blog.csdn.net/yuanshenqiang/article/details/129927806
#elif __ANDROID__

#endif


// 使用 #pragma section 创建一个名为 ".my_custom_section" 的节，并标记为可执行
//#pragma section(".my_custom_section", execute)





int test() {
    
    node* ss = &section_start[0];
    node* ee = &section_end[0];
    // 创建的section大小以及可以存放的node数量由编译器相关参数确定
    printf("section size = %d, element count=%d.\n", (ee - ss) * sizeof(node), ee - ss);
    int id = 0;
    for (; ss < ee; ss++, id++)
    {
        if (ss->func != NULL)
        {
            printf("find a valid element in this section, id=%d, name=%s.\n", id, ss->name);
            //( (void*)())(ss->func);
            ((void(*)())((ss->func)))();
        }
            
        
        //section被初始化的时候全部置0，所以ss->func为0的时候表明此处未使用
    }
   


    return 0;
}

int testiins(int ats)
{
    return 0;
}

