#ifndef DATA_TYPE
#define DATA_TYPE

typedef struct vec2
{
    float X;
    float Y;
} Vector2;
typedef struct vec3
{
    float X;
    float Y;
    float Z;
} Vector3;
typedef struct vec4
{
    float X;
    float Y;
    float Z;
    float W;
} Vector4;
typedef struct matrix
{
    float _11, _12, _13, _14;
    float _21, _22, _23, _24;
    float _31, _32, _33, _34;
    float _41, _42, _43, _44;
} Matrix;

enum
{
    Instruction = 0x1,
    Stack = 0x10,
    Register = 0x100
};

typedef int Bool;
#define False 0
#define True 1

#endif
