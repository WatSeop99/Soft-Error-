#ifndef MATH
#define MATH

// Row major
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

float AddF(const float, const float);
float SubF(const float, const float);
float MulF(const float, const float);
float DivF(const float, const float);

Vector2 AddVec2(const Vector2, const Vector2);
Vector2 SubVec2(const Vector2, const Vector2);
Vector2 MulVec2(const Vector2, const Vector2); // Dot product
Vector2 DivVec2(const Vector2, const Vector2);

Vector3 AddVec3(const Vector3, const Vector3);
Vector3 SubVec3(const Vector3, const Vector3);
Vector3 MulVec3(const Vector3, const Vector3); // Dot product
Vector3 DivVec3(const Vector3, const Vector3);

Vector4 AddVec4(const Vector4, const Vector4);
Vector4 SubVec4(const Vector4, const Vector4);
Vector4 MulVec4(const Vector4, const Vector4); // Dot product
Vector4 DivVec4(const Vector4, const Vector4);

Matrix AddMat(const Matrix, const Matrix);
Matrix SubMat(const Matrix, const Matrix);
Matrix MulMat(const Matrix, const Matrix);

Vector4 MulVecAndMat(const Vector4, const Matrix);

#endif
