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

    void TestPipeLine(const char *addr, const std::string& from) {
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
    TestPipeLine("inproc://a", "123");
    TestPipeLine("inproc://b", "123123123");
}

TEST_F(SocketTest, IPCSendRecv) {
    TestPipeLine("ipc://a", "123");
    TestPipeLine("ipc://b", "123123123");
}

TEST_F(SocketTest, TCPSendRecv) {
    TestPipeLine("tcp://127.0.0.1:90", "123");
    TestPipeLine("tcp://127.0.0.1:91", "abcdef");
}

TEST_F(SocketTest, WSSendRecv) {
    TestPipeLine("ws://127.0.0.1:90", "123");
    TestPipeLine("ws://127.0.0.1:91", "123123123");
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
        auto rep = std::make_shared <Socket>(AF::SP, NN_REP);
        ASSERT_TRUE(rep);
        rep->Bind(addr);

        auto req = std::make_shared <Socket>(AF::SP, NN_REQ);
        ASSERT_TRUE(req);
        req->Connect(addr);

        poller_->AddSocket(rep->fd(), [=] {
            Msg msg;
            rep->Recv(msg);
            if (msg.size() > 0) {
                rep->Send(msg);
            }
        }, nullptr);

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

        poller_->DelSocket(rep->fd(), [rep]() {
            rep->Close();
        });
    }

protected:
    std::shared_ptr<ThreadPoller> poller_;
};

TEST_F(PollerTest, INPROCReqRep) {
    TestReqRep("inproc://a", 100);
    TestReqRep("inproc://bb", 400);
    TestReqRep("inproc://ccc", 1000);
}

TEST_F(PollerTest, IPCReqRep) {
    TestReqRep("ipc://a", 100);
    TestReqRep("ipc://bb", 400);
    TestReqRep("ipc://ccc", 1000);
}

TEST_F(PollerTest, TCPReqRep) {
    TestReqRep("tcp://127.0.0.1:90", 100);
    TestReqRep("tcp://127.0.0.1:92", 400);
    TestReqRep("tcp://127.0.0.1:93", 1000);
}

TEST_F(PollerTest, WSReqRep) {
    TestReqRep("ws://127.0.0.1:94", 100);
    TestReqRep("ws://127.0.0.1:95", 400);
    TestReqRep("ws://127.0.0.1:96", 1000);
}


int main(int argc, char *argv[]) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}