extern int answer;
int* answer_ptr = &answer;

int set_answer() {
    int make_gcc_do_sub_rsp_for_locals = 0;
    *answer_ptr = 42;
    return 0;
}
