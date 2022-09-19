/* pintos/include/threads/fixed_point.h */
/* Added(Project 1). mlfqs fixed point arithmetic operations */

#include <stdint.h>
#define F (1<<14) // Fixed point 1
#define INT_MAX ((1 << 31) - 1)
#define INT_MIN (-(1 << 31))

/* x, y: fixed point numbers(17.14 fmt)
    n: integer */

int int_to_fp(int n); /* integer to fixed point */
int fp_to_int_round(int x); /* fixed point to int(round) */
int fp_to_int(int x); /* fixed point to int(discard)*/
int add_fp(int x, int y); /* fixed point addition */
int add_mixed(int x, int n); /* fixed point + integer */
int sub_fp(int x, int y); /* fixed point subtraction */
int sub_mixed(int x, int n); /* fixed point - integer */
int mult_fp(int x, int y); /* fixed point multiplication */
int mult_mixed(int x, int y); /* fixed point * integer */
int div_fp(int x, int y); /* fixed point division */
int div_mixed(int x, int n); /* fixed point / integer */


int int_to_fp (int n) {
  return n * F;
}

int fp_to_int (int x) {
  return x / F;
}

int fp_to_int_round (int x) {
  if (x >= 0) return (x + F / 2) / F;
  else return (x - F / 2) / F;
}

int add_fp (int x, int y) {
  return x + y;
}

int sub_fp (int x, int y) {
  return x - y;
}

int add_mixed (int x, int n) {
  return x + n * F;
}

int sub_mixed (int x, int n) {
  return x - n * F;
}

int mult_fp (int x, int y) {
  return ((int64_t) x) * y / F;
}

int mult_mixed (int x, int n) {
  return x * n;
}

int div_fp (int x, int y) {
  return ((int64_t) x) * F / y;
}

int div_mixed (int x, int n) {
  return x / n;
}
