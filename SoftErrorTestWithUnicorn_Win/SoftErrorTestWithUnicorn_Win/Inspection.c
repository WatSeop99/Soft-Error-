#include "DataType.h"
#include "Inspection.h"

int InspectEmulationResult(uc_engine* pUC)
{
	if (!pUC)
	{
		return -1;
	}

	int ret = 0;
	float margin = 0.000001f;

	float floatResult = 0.0f;
	Vector2 vec2Result = { 0.0f, };
	Vector3 vec3Result = { 0.0f, };
	Vector4 vec4Result = { 0.0f, };
	Matrix matResult = { 0.0f, };

	// print global variable in memory.
	uc_mem_read(pUC, 0xdd0c, (void*)(&floatResult), sizeof(float));
	uc_mem_read(pUC, 0xdd10, (void*)(&vec2Result), sizeof(Vector2));
	uc_mem_read(pUC, 0xdd18, (void*)(&vec3Result), sizeof(Vector3));
	uc_mem_read(pUC, 0xdd24, (void*)(&vec4Result), sizeof(Vector4));
	uc_mem_read(pUC, 0xdd34, (void*)(&matResult), sizeof(Matrix));

	// compare the result to given value.

	// compare float result.
	if (floatResult < 2.0f - margin || floatResult > 2.0f + margin)
	{
		ret = -1;
		goto LB_RET;
	}

	// compare vec2 result.
	if (vec2Result.X < 2.0f - margin || vec2Result.X > 2.0f + margin)
	{
		ret = -1;
		goto LB_RET;
	}
	if (vec2Result.Y < 1.0f - margin || vec2Result.Y > 2.0f + margin)
	{
		ret = -1;
		goto LB_RET;
	}

	// comapre vec3 result.
	if (vec3Result.X < -margin || vec3Result.X > margin)
	{
		ret = -1;
		goto LB_RET;
	}
	if (vec3Result.Y < 0.375f - margin || vec3Result.Y > 0.375f + margin)
	{
		ret = -1;
		goto LB_RET;
	}
	if (vec3Result.Z < 0.75f - margin || vec3Result.Z > 0.75f + margin)
	{
		ret = -1;
		goto LB_RET;
	}

	// compare vec4 result.
	if (vec4Result.X < -0.55f - margin || vec4Result.X > -0.55f + margin)
	{
		ret = -1;
		goto LB_RET;
	}
	if (vec4Result.Y < -0.5f - margin || vec4Result.Y > -0.5f + margin)
	{
		ret = -1;
		goto LB_RET;
	}
	if (vec4Result.Z < -margin || vec4Result.Z > margin)
	{
		ret = -1;
		goto LB_RET;
	}
	if (vec4Result.W < -margin || vec4Result.W > margin)
	{
		ret = -1;
		goto LB_RET;
	}

	// compare matrix result.
	if (matResult._11 < 2.0f - margin || matResult._11 > 2.0f + margin)
	{
		ret = -1;
		goto LB_RET;
	}
	if (matResult._12 < 1.0f - margin || matResult._12 > 1.0f + margin)
	{
		ret = -1;
		goto LB_RET;
	}
	if (matResult._13 < 0.45f - margin || matResult._13 > 0.45f + margin)
	{
		ret = -1;
		goto LB_RET;
	}
	if (matResult._14 < 1.0f - margin || matResult._14 > 1.0f + margin)
	{
		ret = -1;
		goto LB_RET;
	}

	if (matResult._21 < 2.1f - margin || matResult._21 > 2.1f + margin)
	{
		ret = -1;
		goto LB_RET;
	}
	if (matResult._22 < 0.45f - margin || matResult._22 > 0.45f + margin)
	{
		ret = -1;
		goto LB_RET;
	}
	if (matResult._23 < 0.75f - margin || matResult._23 > 0.75f + margin)
	{
		ret = -1;
		goto LB_RET;
	}
	if (matResult._24 < 0.6f - margin || matResult._24 > 0.6f + margin)
	{
		ret = -1;
		goto LB_RET;
	}

	if (matResult._31 < 1.0f - margin || matResult._31 > 1.0f + margin)
	{
		ret = -1;
		goto LB_RET;
	}
	if (matResult._32 < 78.0f - margin || matResult._32 > 78.0f + margin)
	{
		ret = -1;
		goto LB_RET;
	}
	if (matResult._33 < 12.3f - margin || matResult._33 > 12.3f + margin)
	{
		ret = -1;
		goto LB_RET;
	}
	if (matResult._34 < 14.5f - margin || matResult._14 > 14.5f + margin)
	{
		ret = -1;
		goto LB_RET;
	}

	if (matResult._41 < 7.0f - margin || matResult._41 > 7.0f + margin)
	{
		ret = -1;
		goto LB_RET;
	}
	if (matResult._42 < -19.2f - margin || matResult._42 > -19.2f + margin)
	{
		ret = -1;
		goto LB_RET;
	}
	if (matResult._43 < -8.0f - margin || matResult._43 > -8.0f + margin)
	{
		ret = -1;
		goto LB_RET;
	}
	if (matResult._44 < -9.0f - margin || matResult._44 > -9.0f + margin)
	{
		ret = -1;
		goto LB_RET;
	}

LB_RET:
	return ret;
}