// #include <stdio.h>
#define f (1 << 14)

int fp_ItoFp(int i) {
    return i * f;
}

int fp_FptoI(int fp_x) {
    return fp_x / f;
}

int fp_FpAdd(int fp_x, int fp_y) {
    return fp_x + fp_y;
}

int fp_FpAddI(int fp_x, int y) {
    return fp_x + fp_ItoFp(y);
}

int fp_FpDivI(int fp_x, int y) {
    return fp_x / y;
}

int fp_FpMulI(int fp_x, int y) {
    return fp_x * y;
} 

int fp_FpMul(int fp_x, int fp_y) {
    return ((int64_t) fp_x) * fp_y / f;
}

int fp_FpDiv(int fp_x, int fp_y) {
    return ((int64_t) fp_x) * f / fp_y;
}

int fp_FptoI_Round(int fp_x) {
    if (fp_x >= 0) {
        return (fp_x + f / 2) / f;
    }
    else {
        return (fp_x - f / 2) / f;
    }
}
