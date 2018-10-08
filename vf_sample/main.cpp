#include <iostream>

class base
{
public:
    int a;
    int b;
    base() { std::cout << "base constructor" << std::endl; }
    virtual void print() { std::cout << "print base" << std::endl; }
    virtual void another() { std::cout << "base another" << std::endl; }
};

class derived : public base
{
public:
    derived() { std::cout << "derived constructor" << std::endl; }
    virtual void print() { std::cout << "print derived" << std::endl; }
    virtual void another() { std::cout << "derived another" << std::endl; }
};

int main(int argc, char* argv[])
{
    base* b = new derived();
    b->print();
    b->another();
    system("PAUSE");
    return 0;
}