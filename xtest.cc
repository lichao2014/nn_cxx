#include "nn_cxx.h"

#include <thread>
#include <atomic>
#include <iostream>
#include "pipeline.h"

using namespace nn_cxx;

namespace {

class ThreadPoller : public Poller {
public:
    void Start() {
        closed_ = false;

        th_ = std::thread([this] {
            while (!closed_ && (Poll(100) >= 0));
        });
    }

    void Stop() {
        closed_ = true;
        th_.join();
    }

private:
    std::thread th_;
    std::atomic_bool closed_ = false;
};
}


int main() {
    auto  poller = std::make_shared<ThreadPoller>();

    poller->Start();

    std::shared_ptr<Socket> a;
    a = poller->AddSocket(AF::SP, NN_PULL, [&a] {
        char buf[64];
        int ret = a->Recv(buf, 64, DONTWAIT);
        std::clog << "recv ret=" << ret << std::endl;
    }, {});
    a->Bind("ipc://a");
    a->Bind("tcp://127.0.0.1:7777");


    std::shared_ptr<Socket> b;
    b = poller->AddSocket(AF::SP, NN_PUSH, {}, [&b] {
        int ret = b->Send("123", 3, DONTWAIT);
        if (ret <= 0) {
            std::clog << "send ret=" << ret << std::endl;
        }
    });
    b->Connet("ipc://a");


    std::cin.get();

    poller->Stop();
}