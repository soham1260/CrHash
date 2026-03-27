__device__  void indexToPassword(long long idx, char* pwd, size_t input_len) // convert each of 94^SIZE combinations to respective string
{
    for (int i = input_len-1 ; i >= 0 ; i--) 
    {
        pwd[i] = '!' + (idx % 94);
        idx /= 94;
    }
}