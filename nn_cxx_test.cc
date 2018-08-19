#include "nn_cxx.h"
#include "gtest/gtest.h"

#include "pipeline.h"
#include "reqrep.h"

using namespace nn_cxx;

class SocketTest : public testing::Test {
public:
    void SetUp() override {
        socket_.reset(new Socket(AF::SP, NN_PUSH));
    }

    void TearDown() override {
        socket_.reset();
    }

    void TestSendRecv(const char *addr, const std::string& from) {
        auto a = std::make_unique<Socket>(AF::SP, NN_PUSH);
        auto b = std::make_unique<Socket>(AF::SP, NN_PULL);

        b->Bind(addr);
        a->Connect(addr);

        int ret = a->Send(from.data(), from.length());
        ASSERT_EQ(ret, from.length());

        std::string to(from.length(), '\0');
        ret = b->Recv(to.data(), to.length());
        ASSERT_EQ(ret, to.length());

        ASSERT_TRUE(std::equal(from.begin(), from.end(), to.begin(), to.end()));
    }

protected:
    std::unique_ptr<Socket> socket_;
};

TEST_F(SocketTest, Bind) {
    std::error_code ec;
    socket_->Bind("a", ec);
    ASSERT_TRUE(ec);

    ec.clear();
    socket_->Bind("inproc://a", ec);
    ASSERT_FALSE(ec);

    ec.clear();
    socket_->Bind("inproc://a", ec);
    ASSERT_TRUE(ec);

    ec.clear();
    socket_->Bind("ipc://a", ec);
    ASSERT_FALSE(ec);

    ec.clear();
    socket_->Bind("tcp://127.0.0.1:90", ec);
    ASSERT_FALSE(ec);

    ec.clear();
    socket_->Bind("ws://127.0.0.1:91", ec);
    ASSERT_FALSE(ec);
}

TEST_F(SocketTest, Connect) {
    std::error_code ec;
    socket_->Connect("a", ec);
    ASSERT_TRUE(ec);

    ec.clear();
    socket_->Connect("inproc://a", ec);
    ASSERT_FALSE(ec);

    ec.clear();
    socket_->Connect("inproc://a", ec);
    ASSERT_FALSE(ec);
}

TEST_F(SocketTest, INPROCSendRecv) {
    TestSendRecv("inproc://a", "123");
    TestSendRecv("inproc://b", "123123123");
}

TEST_F(SocketTest, IPCSendRecv) {
    TestSendRecv("ipc://a", "123");
    TestSendRecv("ipc://b", "123123123");
}

TEST_F(SocketTest, TCPSendRecv) {
    TestSendRecv("tcp://127.0.0.1:90", "123");
    TestSendRecv("tcp://127.0.0.1:91", "abcdef");
}

TEST_F(SocketTest, WSSendRecv) {
    TestSendRecv("ws://127.0.0.1:90", "123");
    TestSendRecv("ws://127.0.0.1:91", "123123123");
}

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

class PollerTest : public testing::Test {
public:
    void SetUp() override {
        poller_.reset(new ThreadPoller);
        poller_->Start();
    }

    void TearDown() override {
        poller_->Stop();
    }

    void TestReqRep(const char *addr, int count) {
        std::shared_ptr<Socket> req;
        std::shared_ptr<Socket> rep;

        rep = poller_->AddSocket(AF::SP, NN_REP, [&rep] {
            void *buf;
            int ret = rep->Recv(&buf);
            rep->Send(buf, ret);
        }, {});
        ASSERT_TRUE(rep);

        rep->Bind(addr);

        req = std::make_shared <Socket>(AF::SP, NN_REQ);
        ASSERT_TRUE(req);

        req->Connect(addr);

        char buf1[64];
        char buf2[64];

        for (int i = 0; i < count; ++i) {
            snprintf(buf1, 64, "%d", i);

            int ret = req->Send(buf1, 64);
            ASSERT_EQ(ret, 64);

            ret = req->Recv(buf2, 64);
            ASSERT_EQ(ret, 64);

            ASSERT_TRUE(std::equal(buf1, buf1 + 64, buf2, buf2 + 64));
        }
    }

protected:
    std::shared_ptr<ThreadPoller> poller_;
};


TEST_F(PollerTest, TCPReqRep) {
    TestReqRep("tcp://127.0.0.1:90", 100);
    TestReqRep("tcp://127.0.0.1:92", 400);
    TestReqRep("tcp://127.0.0.1:93", 1000);
}


int main(int argc, char *argv[]) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}