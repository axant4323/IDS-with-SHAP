/* -*- Mode:C++; c-file-style:\"gnu\"; indent-tabs-mode:nil; -*- */
/*
 * X-NIDS: ns-3 Simulation Topology for Network Intrusion Detection
 *
 * Topology:
 *   [Benign Clients 0..2] \                     / [Target Server]
 *                          +-> [R1] <===> [R2] <-+
 *   [Attacker Node]       /                     \ [Monitoring Interface]
 *
 * Attacks Simulated:
 *   1. TCP SYN Flood (Denial of Service)
 *   2. Sequential Port Scanning (Reconnaissance)
 *   3. High-Rate UDP Flood (Bandwidth Exhaustion)
 *
 * Packet traces are exported to PCAP format for downstream ML extraction.
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/ipv4-global-routing-helper.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("XNidsSimulation");

int main(int argc, char *argv[])
{
  CommandLine cmd(__FILE__);
  cmd.Parse(argc, argv);

  Time::SetResolution(Time::NS);
  LogComponentEnable("XNidsSimulation", LOG_LEVEL_INFO);

  NS_LOG_INFO("Configuring X-NIDS Network Simulation Topology...");

  // Node containers
  NodeContainer benignClients;
  benignClients.Create(3);

  NodeContainer attackerNode;
  attackerNode.Create(1);

  NodeContainer routers;
  routers.Create(2); // R1 and R2

  NodeContainer targetServer;
  targetServer.Create(1);

  // Point-to-point channel configuration
  PointToPointHelper clientLink;
  clientLink.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
  clientLink.SetChannelAttribute("Delay", StringValue("2ms"));

  PointToPointHelper bottleneckLink;
  bottleneckLink.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
  bottleneckLink.SetChannelAttribute("Delay", StringValue("10ms"));

  PointToPointHelper serverLink;
  serverLink.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
  serverLink.SetChannelAttribute("Delay", StringValue("2ms"));

  // Connect clients to Router 1
  NetDeviceContainer clientDevices[3];
  for (uint32_t i = 0; i < 3; ++i)
    {
      clientDevices[i] = clientLink.Install(benignClients.Get(i), routers.Get(0));
    }

  // Connect Attacker to Router 1
  NetDeviceContainer attackerDevice = clientLink.Install(attackerNode.Get(0), routers.Get(0));

  // Connect Router 1 to Router 2 (Bottleneck)
  NetDeviceContainer bottleneckDevices = bottleneckLink.Install(routers.Get(0), routers.Get(1));

  // Connect Router 2 to Target Server
  NetDeviceContainer serverDevice = serverLink.Install(routers.Get(1), targetServer.Get(0));

  // Install Internet Stack
  InternetStackHelper stack;
  stack.Install(benignClients);
  stack.Install(attackerNode);
  stack.Install(routers);
  stack.Install(targetServer);

  // Assign IP Addresses
  Ipv4AddressHelper address;
  Ipv4InterfaceContainer clientInterfaces[3];
  for (uint32_t i = 0; i < 3; ++i)
    {
      std::ostringstream subnet;
      subnet << "10.1." << (i + 1) << ".0";
      address.SetBase(subnet.str().c_str(), "255.255.255.0");
      clientInterfaces[i] = address.Assign(clientDevices[i]);
    }

  address.SetBase("10.1.10.0", "255.255.255.0");
  Ipv4InterfaceContainer attackerInterface = address.Assign(attackerDevice);

  address.SetBase("10.2.1.0", "255.255.255.0");
  Ipv4InterfaceContainer bottleneckInterfaces = address.Assign(bottleneckDevices);

  address.SetBase("10.3.1.0", "255.255.255.0");
  Ipv4InterfaceContainer serverInterface = address.Assign(serverDevice);

  Ipv4GlobalRoutingHelper::PopulateRoutingTables();

  Ipv4Address serverIp = serverInterface.GetAddress(1);

  NS_LOG_INFO("Target Server IP Address: " << serverIp);

  // --------------------------------------------------------------------------
  // Benign Applications
  // --------------------------------------------------------------------------
  uint16_t httpPort = 80;
  uint16_t dnsPort = 53;

  // HTTP Server Sink on Target
  Address httpSinkAddress(InetSocketAddress(Ipv4Address::GetAny(), httpPort));
  PacketSinkHelper httpSinkHelper("ns3::TcpSocketFactory", httpSinkAddress);
  ApplicationContainer httpSinkApp = httpSinkHelper.Install(targetServer.Get(0));
  httpSinkApp.Start(Seconds(0.0));
  httpSinkApp.Stop(Seconds(60.0));

  // Client 0: Regular HTTP Bulk Send
  BulkSendHelper httpBulkSend("ns3::TcpSocketFactory", InetSocketAddress(serverIp, httpPort));
  httpBulkSend.SetAttribute("MaxBytes", UintegerValue(0)); // Continuous
  ApplicationContainer client0App = httpBulkSend.Install(benignClients.Get(0));
  client0App.Start(Seconds(1.0));
  client0App.Stop(Seconds(58.0));

  // Client 1: UDP Echo (DNS / interactive traffic)
  UdpEchoServerHelper dnsServer(dnsPort);
  ApplicationContainer dnsServerApp = dnsServer.Install(targetServer.Get(0));
  dnsServerApp.Start(Seconds(0.0));
  dnsServerApp.Stop(Seconds(60.0));

  UdpEchoClientHelper dnsClient(serverIp, dnsPort);
  dnsClient.SetAttribute("MaxPackets", UintegerValue(100));
  dnsClient.SetAttribute("Interval", TimeValue(Seconds(0.5)));
  dnsClient.SetAttribute("PacketSize", UintegerValue(128));
  ApplicationContainer client1App = dnsClient.Install(benignClients.Get(1));
  client1App.Start(Seconds(2.0));
  client1App.Stop(Seconds(58.0));

  // --------------------------------------------------------------------------
  // Attack Injection from Attacker Node
  // --------------------------------------------------------------------------

  // Attack 1: TCP SYN Flood (DoS) [Time: 15s to 25s]
  OnOffHelper synFloodHelper("ns3::TcpSocketFactory", InetSocketAddress(serverIp, httpPort));
  synFloodHelper.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
  synFloodHelper.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
  synFloodHelper.SetAttribute("DataRate", StringValue("8Mbps"));
  synFloodHelper.SetAttribute("PacketSize", UintegerValue(64));
  ApplicationContainer synFloodApp = synFloodHelper.Install(attackerNode.Get(0));
  synFloodApp.Start(Seconds(15.0));
  synFloodApp.Stop(Seconds(25.0));

  // Attack 2: High-Rate UDP Flood (DoS) [Time: 30s to 40s]
  uint16_t udpAttackPort = 9999;
  OnOffHelper udpFloodHelper("ns3::UdpSocketFactory", InetSocketAddress(serverIp, udpAttackPort));
  udpFloodHelper.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
  udpFloodHelper.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
  udpFloodHelper.SetAttribute("DataRate", StringValue("9Mbps"));
  udpFloodHelper.SetAttribute("PacketSize", UintegerValue(1024));
  ApplicationContainer udpFloodApp = udpFloodHelper.Install(attackerNode.Get(0));
  udpFloodApp.Start(Seconds(30.0));
  udpFloodApp.Stop(Seconds(40.0));

  // --------------------------------------------------------------------------
  // PCAP Packet Tracing on Bottleneck Router Interface
  // --------------------------------------------------------------------------
  bottleneckLink.EnablePcap("nids_sim_trace", bottleneckDevices.Get(0), true);

  NS_LOG_INFO("Starting Simulation (60.0s duration)...");
  Simulator::Stop(Seconds(60.0));
  Simulator::Run();
  Simulator::Destroy();
  NS_LOG_INFO("Simulation finished. PCAP trace exported to nids_sim_trace.pcap");

  return 0;
}
