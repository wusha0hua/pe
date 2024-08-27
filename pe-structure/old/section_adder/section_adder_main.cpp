#include"section_adder.h"
#include<windows.h>
#include<stdio.h>
using namespace std;



int main()
{
    char filepath[100];
    printf("input file path:");
    scanf("%s",filepath);
    bool flag=section_adder(filepath);
    if(flag==1)
    {
        printf("success");
    }
    else
    {
        printf("fail");
    }
}