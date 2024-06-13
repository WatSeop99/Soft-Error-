// #include <assert.h>
#include "Math.h"

float AddF(const float A, const float B)
{
    return A + B;
}

float SubF(const float A, const float B)
{
    return A - B;
}

float MulF(const float A, const float B)
{
    return A * B;
}

float DivF(const float A, const float B)
{
    // assert(B != 0.0f);
    return A / B;
}

Vector2 AddVec2(const Vector2 A, const Vector2 B)
{
    Vector2 ret = { 0, };
    ret.X = A.X + B.X;
    ret.Y = A.Y + B.Y;

    return ret;
}
Vector2 SubVec2(const Vector2 A, const Vector2 B)
{
    Vector2 ret = { 0, };
    ret.X = A.X - B.X;
    ret.Y = A.Y - B.Y;

    return ret;
}
Vector2 MulVec2(const Vector2 A, const Vector2 B)
{
    Vector2 ret = { 0, };
    ret.X = A.X * B.X;
    ret.Y = A.Y * B.Y;

    return ret;
}
Vector2 DivVec2(const Vector2 A, const Vector2 B)
{
    // assert(B.X != 0.0f && B.Y != 0.0f);
    
    Vector2 ret = { 0, };
    ret.X = A.X / B.X;
    ret.Y = A.Y / B.Y;

    return ret;
}

Vector3 AddVec3(const Vector3 A, const Vector3 B)
{
    Vector3 ret = { 0, };
    ret.X = A.X + B.X;
    ret.Y = A.Y + B.Y;
    ret.Z = A.Z + B.Z;

    return ret;
}
Vector3 SubVec3(const Vector3 A, const Vector3 B)
{
    Vector3 ret = { 0, };
    ret.X = A.X + B.X;
    ret.Y = A.Y + B.Y;
    ret.Z = A.Z + B.Z;

    return ret;
}
Vector3 MulVec3(const Vector3 A, const Vector3 B)
{
    Vector3 ret = { 0, };
    ret.X = A.X * B.X;
    ret.Y = A.Y * B.Y;
    ret.Z = A.Z * B.Z;

    return ret;
}
Vector3 DivVec3(const Vector3 A, const Vector3 B)
{
    // assert(B.X != 0.0f && B.Y != 0.0f && B.Z != 0.0f);

    Vector3 ret = { 0, };
    ret.X = A.X / B.X;
    ret.Y = A.Y / B.Y;
    ret.Z = A.Z / B.Z;

    return ret;
}

Vector4 AddVec4(const Vector4 A, const Vector4 B)
{
    Vector4 ret = { 0, };
    ret.X = A.X + B.X;
    ret.Y = A.Y + B.Y;
    ret.Z = A.Z + B.Z;
    ret.W = A.W + B.W;

    return ret;
}
Vector4 SubVec4(const Vector4 A, const Vector4 B)
{
    Vector4 ret = { 0, };
    ret.X = A.X - B.X;
    ret.Y = A.Y - B.Y;
    ret.Z = A.Z - B.Z;
    ret.W = A.W - B.W;

    return ret;
}
Vector4 MulVec4(const Vector4 A, const Vector4 B)
{
    Vector4 ret = { 0, };
    ret.X = A.X * B.X;
    ret.Y = A.Y * B.Y;
    ret.Z = A.Z * B.Z;
    ret.W = A.W * B.W;

    return ret;
}
Vector4 DivVec4(const Vector4 A, const Vector4 B)
{
    // assert(B.X != 0.0f && B.Y != 0.0f && B.Z != 0.0f && B.W != 0.0f);

    Vector4 ret = { 0, };
    ret.X = A.X / B.X;
    ret.Y = A.Y / B.Y;
    ret.Z = A.Z / B.Z;
    ret.W = A.W / B.W;

    return ret;
}

Matrix AddMat(const Matrix A, const Matrix B)
{
    Matrix ret = { 0, };

    ret._11 = A._11 + B._11;
    ret._12 = A._12 + B._12;
    ret._13 = A._13 + B._13;
    ret._14 = A._14 + B._14;

    ret._21 = A._21 + B._21;
    ret._22 = A._22 + B._22;
    ret._23 = A._23 + B._23;
    ret._24 = A._24 + B._24;

    ret._31 = A._31 + B._31;
    ret._32 = A._32 + B._32;
    ret._33 = A._33 + B._33;
    ret._34 = A._34 + B._34;

    ret._41 = A._41 + B._41;
    ret._42 = A._42 + B._42;
    ret._43 = A._43 + B._43;
    ret._44 = A._44 + B._44;

    return ret;
}
Matrix SubMat(const Matrix A, const Matrix B)
{
    Matrix ret = { 0, };

    ret._11 = A._11 - B._11;
    ret._12 = A._12 - B._12;
    ret._13 = A._13 - B._13;
    ret._14 = A._14 - B._14;

    ret._21 = A._21 - B._21;
    ret._22 = A._22 - B._22;
    ret._23 = A._23 - B._23;
    ret._24 = A._24 - B._24;

    ret._31 = A._31 - B._31;
    ret._32 = A._32 - B._32;
    ret._33 = A._33 - B._33;
    ret._34 = A._34 - B._34;

    ret._41 = A._41 - B._41;
    ret._42 = A._42 - B._42;
    ret._43 = A._43 - B._43;
    ret._44 = A._44 - B._44;

    return ret;
}
Matrix MulMat(const Matrix A, const Matrix B)
{
    Matrix ret = { 0, };

    ret._11 = A._11 * B._11 + A._12 * B._21 + A._13 * B._31 + A._14 * B._41;
    ret._12 = A._11 * B._12 + A._12 * B._22 + A._13 * B._32 + A._14 * B._42;
    ret._13 = A._11 * B._13 + A._12 * B._23 + A._13 * B._33 + A._14 * B._43;
    ret._14 = A._11 * B._14 + A._12 * B._24 + A._13 * B._34 + A._14 * B._44;

    ret._21 = A._21 * B._11 + A._22 * B._21 + A._23 * B._31 + A._24 * B._41;
    ret._22 = A._21 * B._12 + A._22 * B._22 + A._23 * B._32 + A._24 * B._42;
    ret._23 = A._21 * B._13 + A._22 * B._23 + A._23 * B._33 + A._24 * B._43;
    ret._24 = A._21 * B._14 + A._22 * B._24 + A._23 * B._34 + A._24 * B._44;

    ret._31 = A._31 * B._11 + A._32 * B._21 + A._33 * B._31 + A._34 * B._41;
    ret._32 = A._31 * B._12 + A._32 * B._22 + A._33 * B._32 + A._34 * B._42;
    ret._33 = A._31 * B._13 + A._32 * B._23 + A._33 * B._33 + A._34 * B._43;
    ret._34 = A._31 * B._14 + A._32 * B._24 + A._33 * B._34 + A._34 * B._44;

    ret._41 = A._41 * B._11 + A._42 * B._21 + A._43 * B._31 + A._44 * B._41;
    ret._42 = A._41 * B._12 + A._42 * B._22 + A._43 * B._32 + A._44 * B._42;
    ret._43 = A._41 * B._13 + A._42 * B._23 + A._43 * B._33 + A._44 * B._43;
    ret._44 = A._41 * B._14 + A._42 * B._24 + A._43 * B._34 + A._44 * B._44;

    return ret;
}

Vector4 MulVecAndMat(const Vector4 VEC, const Matrix MAT)
{
    Vector4 ret = { 0, };

    ret.X = VEC.X * MAT._11 + VEC.Y * MAT._21 + VEC.Z * MAT._31 + VEC.W * MAT._41;
    ret.Y = VEC.X * MAT._12 + VEC.Y * MAT._22 + VEC.Z * MAT._32 + VEC.W * MAT._42;
    ret.Z = VEC.X * MAT._13 + VEC.Y * MAT._23 + VEC.Z * MAT._33 + VEC.W * MAT._43;
    ret.W = VEC.X * MAT._14 + VEC.Y * MAT._24 + VEC.Z * MAT._34 + VEC.W * MAT._44;

    return ret;
}
