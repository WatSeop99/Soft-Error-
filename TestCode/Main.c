#include <stdio.h>
#include "Math.h"

float g_FloatResult = 0.0f;
Vector2 g_Vec2Result = {0.0f, };
Vector3 g_Vec3Result = {0.0f, };
Vector4 g_Vec4Result = {0.0f, };
Matrix g_MatResult = {0.0f, };

int main()
{
    // Test1
    g_FloatResult = MulF(1.0f, 2.0f);

    // Test2
    Vector2 a = {1.0f, 0.0f};
    Vector2 b = {1.0f, 1.0f};
    g_Vec2Result = AddVec2(a, b);
    
    // Test3
    Vector3 x = {1.0f, 0.5f, 0.5f};
    Vector3 y = {0.0f, 0.75f, 1.5f};
    g_Vec3Result = MulVec3(x, y);

    // Test4
    Vector4 i = {0.45f, 0.5f, 1.0f, 1.0f};
    Vector4 j = {1.0f, 1.0f, 1.0f, 1.0f};
    g_Vec4Result = SubVec4(i, j);

    // Test5
    Matrix mat1 = {
        1.0f, 0.0f, 0.0f, 0.0f,
        0.0f, 1.0f, 0.0f, 0.0f,
        0.0f, 0.0f, 1.0f, 0.0f,
        0.0f, 0.0f, 0.0f, 1.0f
    };
    Matrix mat2 = {
        2.0f, 1.0f, 0.45f, 1.0f, 
        2.1f, 0.45f, 0.75f, 0.6f,
        1.0f, 78.0f, 12.3f, 14.5f,
        7.0f, -19.2f, -8.0f, -9.0f
    };
    g_MatResult = MulMat(mat1, mat2);

    int correct = (g_FloatResult == 3.0f);
    
    return correct;
}
