//
// Copyright (c) 2018 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package virtcontainers

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"testing"

	"github.com/containers/virtcontainers/pkg/mock"
	gpb "github.com/gogo/protobuf/types"
	pb "github.com/kata-containers/agent/protocols/grpc"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

var testKataProxyURLTempl = "unix://%s/kata-proxy-test.sock"

func proxyHandlerDiscard(c net.Conn) {
	buf := make([]byte, 1024)
	c.Read(buf)
}

func testGenerateKataProxySockDir() (string, error) {
	dir, err := ioutil.TempDir("", "kata-proxy-test")
	if err != nil {
		return "", err
	}

	return dir, nil
}

func TestKataAgentConnect(t *testing.T) {
	proxy := mock.ProxyUnixMock{
		ClientHandler: proxyHandlerDiscard,
	}

	sockDir, err := testGenerateKataProxySockDir()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)

	testKataProxyURL := fmt.Sprintf(testKataProxyURLTempl, sockDir)
	if err := proxy.Start(testKataProxyURL); err != nil {
		t.Fatal(err)
	}
	defer proxy.Stop()

	k := &kataAgent{
		state: KataAgentState{
			URL: testKataProxyURL,
		},
	}

	if err := k.connect(); err != nil {
		t.Fatal(err)
	}

	if k.client == nil {
		t.Fatal("Kata agent client is not properly initialized")
	}
}

func TestKataAgentDisconnect(t *testing.T) {
	proxy := mock.ProxyUnixMock{
		ClientHandler: proxyHandlerDiscard,
	}

	sockDir, err := testGenerateKataProxySockDir()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)

	testKataProxyURL := fmt.Sprintf(testKataProxyURLTempl, sockDir)
	if err := proxy.Start(testKataProxyURL); err != nil {
		t.Fatal(err)
	}
	defer proxy.Stop()

	k := &kataAgent{
		state: KataAgentState{
			URL: testKataProxyURL,
		},
	}

	if err := k.connect(); err != nil {
		t.Fatal(err)
	}

	if err := k.disconnect(); err != nil {
		t.Fatal(err)
	}

	if k.client != nil {
		t.Fatal("Kata agent client pointer should be nil")
	}
}

type gRPCProxy struct{}

var emptyResp = &gpb.Empty{}

func (p *gRPCProxy) CreateContainer(ctx context.Context, req *pb.CreateContainerRequest) (*gpb.Empty, error) {
	return emptyResp, nil
}

func (p *gRPCProxy) StartContainer(ctx context.Context, req *pb.StartContainerRequest) (*gpb.Empty, error) {
	return emptyResp, nil
}

func (p *gRPCProxy) ExecProcess(ctx context.Context, req *pb.ExecProcessRequest) (*gpb.Empty, error) {
	return emptyResp, nil
}

func (p *gRPCProxy) SignalProcess(ctx context.Context, req *pb.SignalProcessRequest) (*gpb.Empty, error) {
	return emptyResp, nil
}

func (p *gRPCProxy) WaitProcess(ctx context.Context, req *pb.WaitProcessRequest) (*pb.WaitProcessResponse, error) {
	return &pb.WaitProcessResponse{}, nil
}

func (p *gRPCProxy) RemoveContainer(ctx context.Context, req *pb.RemoveContainerRequest) (*gpb.Empty, error) {
	return emptyResp, nil
}

func (p *gRPCProxy) WriteStdin(ctx context.Context, req *pb.WriteStreamRequest) (*pb.WriteStreamResponse, error) {
	return &pb.WriteStreamResponse{}, nil
}

func (p *gRPCProxy) ReadStdout(ctx context.Context, req *pb.ReadStreamRequest) (*pb.ReadStreamResponse, error) {
	return &pb.ReadStreamResponse{}, nil
}

func (p *gRPCProxy) ReadStderr(ctx context.Context, req *pb.ReadStreamRequest) (*pb.ReadStreamResponse, error) {
	return &pb.ReadStreamResponse{}, nil
}

func (p *gRPCProxy) CloseStdin(ctx context.Context, req *pb.CloseStdinRequest) (*gpb.Empty, error) {
	return emptyResp, nil
}

func (p *gRPCProxy) TtyWinResize(ctx context.Context, req *pb.TtyWinResizeRequest) (*gpb.Empty, error) {
	return emptyResp, nil
}

func (p *gRPCProxy) CreateSandbox(ctx context.Context, req *pb.CreateSandboxRequest) (*gpb.Empty, error) {
	return emptyResp, nil
}

func (p *gRPCProxy) DestroySandbox(ctx context.Context, req *pb.DestroySandboxRequest) (*gpb.Empty, error) {
	return emptyResp, nil
}

func (p *gRPCProxy) AddInterface(ctx context.Context, req *pb.AddInterfaceRequest) (*pb.Interface, error) {
	return nil, nil
}

func (p *gRPCProxy) RemoveInterface(ctx context.Context, req *pb.RemoveInterfaceRequest) (*pb.Interface, error) {
	return nil, nil
}

func (p *gRPCProxy) UpdateInterface(ctx context.Context, req *pb.UpdateInterfaceRequest) (*pb.Interface, error) {
	return nil, nil
}

func (p *gRPCProxy) AddRoute(ctx context.Context, req *pb.AddRouteRequest) (*gpb.Empty, error) {
	return emptyResp, nil
}

func (p *gRPCProxy) UpdateRoute(ctx context.Context, req *pb.UpdateRouteRequest) (*gpb.Empty, error) {
	return emptyResp, nil
}

func (p *gRPCProxy) RemoveRoute(ctx context.Context, req *pb.RemoveRouteRequest) (*gpb.Empty, error) {
	return emptyResp, nil
}

func (p *gRPCProxy) OnlineCPUMem(ctx context.Context, req *pb.OnlineCPUMemRequest) (*gpb.Empty, error) {
	return emptyResp, nil
}

func gRPCRegister(s *grpc.Server, srv interface{}) {
	switch g := srv.(type) {
	case *gRPCProxy:
		pb.RegisterAgentServiceServer(s, g)
	}
}

var reqList = []interface{}{
	&pb.CreateSandboxRequest{},
	&pb.DestroySandboxRequest{},
	&pb.ExecProcessRequest{},
	&pb.CreateContainerRequest{},
	&pb.StartContainerRequest{},
	&pb.RemoveContainerRequest{},
	&pb.SignalProcessRequest{},
}

func TestKataAgentSendReq(t *testing.T) {
	impl := &gRPCProxy{}

	proxy := mock.ProxyGRPCMock{
		GRPCImplementer: impl,
		GRPCRegister:    gRPCRegister,
	}

	sockDir, err := testGenerateKataProxySockDir()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)

	testKataProxyURL := fmt.Sprintf(testKataProxyURLTempl, sockDir)
	if err := proxy.Start(testKataProxyURL); err != nil {
		t.Fatal(err)
	}
	defer proxy.Stop()

	k := &kataAgent{
		state: KataAgentState{
			URL: testKataProxyURL,
		},
	}

	for _, req := range reqList {
		if _, err := k.sendReq(req); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGenerateKataInterfacesAndRoutes(t *testing.T) {

	impl := &gRPCProxy{}

	proxy := mock.ProxyGRPCMock{
		GRPCImplementer: impl,
		GRPCRegister:    gRPCRegister,
	}

	sockDir, err := testGenerateKataProxySockDir()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)

	testKataProxyURL := fmt.Sprintf(testKataProxyURLTempl, sockDir)
	if err := proxy.Start(testKataProxyURL); err != nil {
		t.Fatal(err)
	}
	defer proxy.Stop()

	k := &kataAgent{
		state: KataAgentState{
			URL: testKataProxyURL,
		},
	}

	/*
		dst := &net.IPNet{
			IP: net.IPv4(192, 168, 0, 0),
			Mask: net.CIDRMak(24,32),
		}
		ip := net.IPv4(127, 1, 1, 1)
		route := netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst, Src: ip}


		Src:     &net.IPNet{IP: net.IPv4(byte(10), byte(10), byte(thread), 0), Mask: []byte{255, 255, 255, 0}},
		Dst:     &net.IPNet{IP: net.IPv4(byte(10), byte(10), byte(thread), 0), Mask: []byte{255, 255, 255, 0}},

	*/
	var addrs []netlink.Addr
	var routes []netlink.Route

	// Create a couple of addresses
	address1 := &net.IPNet{IP: net.IPv4(172, 17, 0, 2), Mask: net.CIDRMask(16, 32)}
	addr := netlink.Addr{IPNet: address1, Label: "VirtIfacelo"}

	addrs = append(addrs, addr)

	// Create a couple of routes:
	route1 := netlink.Route{LinkIndex: 329, Dst: nil, Src: nil, Gw: net.IPv4(172, 17, 0, 1)}
	routes = append(routes, route1)

	dst2 := &net.IPNet{IP: net.IPv4(172, 17, 0, 0), Mask: net.CIDRMask(16, 32)}
	src2 := net.IPv4(172, 17, 0, 2)
	gw2 := net.IPv4(172, 17, 0, 1)
	route2 := netlink.Route{LinkIndex: 329, Dst: dst2, Src: src2, Gw: gw2}
	routes = append(routes, route2)

	networkInfo := NetworkInfo{
		Iface: NetlinkIface{
			LinkAttrs: netlink.LinkAttrs{MTU: 1500},
			Type:      "",
		},
		Addrs:  addrs,
		Routes: routes,
	}

	ep0 := &PhysicalEndpoint{
		IfaceName:          "eth0",
		HardAddr:           net.HardwareAddr{0x02, 0x00, 0xca, 0xfe, 0x00, 0x04}.String(),
		EndpointProperties: networkInfo,
	}

	var endpoints []Endpoint

	endpoints = append(endpoints, ep0)

	nns := NetworkNamespace{NetNsPath: "foobar", NetNsCreated: true, Endpoints: endpoints}

	resInterfaces, resRoutes, err := k.generateKataInterfacesAndRoutes(nns)
	if err != nil {
		fmt.Println("failure")
	}

	fmt.Println("interfaces: %+v", resInterfaces)
	fmt.Println("routes: %+v", resRoutes)

	/*
	   =========
	   Feb 15 15:09:14 eernstworkstation kata-runtime-cc[107145]: time="2018-02-15T15:09:14-08:00" level=warning msg="endpoint description for reference" endpoint="&
	   {NetPair:
	   	{ID:08db426b-ab5f-480e-af4b-19af86777eb2 Name:br0 VirtIface:
	   		{Name:eth0 HardAddr:02:00:ca:fe:00:00 Addrs:[172.17.0.2/16 eth0]} TAPIface:
	   		{Name:tap0 HardAddr:02:42:ac:11:00:02 Addrs:[]}
	   		NetInterworkingModel:2
	   		VMFds:[0xc42000fa88 0xc42000fa90 0xc42000fa98 0xc42000faa0 0xc42000faa8 0xc42000fab0 0xc42000fab8 0xc42000fac0]
	   		VhostFds:[0xc42000fac8 0xc42000fad0 0xc42000fad8 0xc42000fae0 0xc42000fae8 0xc42000faf0 0xc42000faf8 0xc42000fb00]}
	   		EndpointProperties:
	   		{Iface:
	   			{LinkAttrs:
	   				{Index:329
	   				MTU:1500
	   				TxQLen:0
	   				Name:eth0
	   				HardwareAddr:02:42:ac:11:00:02
	   				Flags:up|broadcast|multicast
	   				RawFlags:69699
	   				ParentIndex:330
	   				MasterIndex:0 Namespace:<nil> Alias: Statistics:0xc4200beb40 Promisc:0 Xdp:<nil> EncapType:ether Protinfo:<nil> OperState:up NetNsID:0 NumTxQueues:0 NumRxQueues:0}
	   			Type:veth}
	   		Addrs:[172.17.0.2/16 eth0]
	   		Routes:[
	   		{Ifindex: 329 Dst: <nil> Src: <nil> Gw: 172.17.0.1 Flags: [] Table: 254}
	   		{Ifindex: 329 Dst: 172.17.0.0/16 Src: 172.17.0.2 Gw: <nil> Flags: [] Table: 254}]
	   		DNS:
	   {Servers:[] Domain: Searches:[] Options:[]}} Physical:false EndpointType:virtual}" source=virtcontainers subsystem=kata_agent


	   ======



	   	linkAttrs := LinkAttrs
	   	{
	   		Name: "etho",
	   	}

	   	addr1 := netlink.Addr {

	   	}
	   	// create a couple of endpoints

	   	networkNS := NetworkNamespace{
	   		NetNsPath:    "foobar",
	   		NetNsCreated: true,
	   		Endpoints:    nil,
	   	}
	*/
}
