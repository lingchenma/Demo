#pragma once
int test();
__declspec(align(16)) struct node
{
    const char* name;
    const void* func;
};

#pragma section("F1")
#pragma section("F1$z")
const int bbb = 10;
int testiins(int ats = bbb);
__declspec(allocate("F1")) __declspec(selectany) node section_start[];
__declspec(allocate("F1$z")) __declspec(selectany) node section_end[];
