;// =======================================================================//
;// !
;// ! Basic stuff
;// !
;// =======================================================================//

PrototypeC pmalloc(size.i);  
PrototypeC pfree(*mem) 
PrototypeC pNomemory() 
PrototypeC ppacket_create(*Data,dataLength.i,flags.l);
PrototypeC ppacket_destroy(*packet);

Structure ENetCallbacks
  *malloc.pmalloc
  *free.pfree     
  *no_memory.pnomemory 
  *packet_create.ppacket_create
  *packet_destroy.ppacket_destroy
EndStructure 
 
;     extern void *enet_malloc(size_t);
;     extern void enet_free(void *);
;     extern ENetPacket* enet_packet_create(const void*,size_t,enet_uint32);
;     extern int enet_packet_resize(ENetPacket*, size_t);
;     extern ENetPacket* enet_packet_copy(ENetPacket*);
;     extern void enet_packet_destroy(ENetPacket*);


 #ENET_PROTOCOL_MINIMUM_MTU             = 576
 #ENET_PROTOCOL_MAXIMUM_MTU             = 4096
 #ENET_PROTOCOL_MAXIMUM_PACKET_COMMANDS = 32
 #ENET_PROTOCOL_MINIMUM_WINDOW_SIZE     = 4096
 #ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE     = 65536
 #ENET_PROTOCOL_MINIMUM_CHANNEL_COUNT   = 1
 #ENET_PROTOCOL_MAXIMUM_CHANNEL_COUNT   = 255
 #ENET_PROTOCOL_MAXIMUM_PEER_ID         = $FFF
 #ENET_PROTOCOL_MAXIMUM_FRAGMENT_COUNT  = 1024 * 1024
 #ENET_PROTOCOL_COMMAND_NONE                     = 0
 #ENET_PROTOCOL_COMMAND_ACKNOWLEDGE              = 1
 #ENET_PROTOCOL_COMMAND_CONNECT                  = 2
 #ENET_PROTOCOL_COMMAND_VERIFY_CONNECT           = 3
 #ENET_PROTOCOL_COMMAND_DISCONNECT               = 4
 #ENET_PROTOCOL_COMMAND_PING                     = 5
 #ENET_PROTOCOL_COMMAND_SEND_RELIABLE            = 6
 #ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE          = 7
 #ENET_PROTOCOL_COMMAND_SEND_FRAGMENT            = 8
 #ENET_PROTOCOL_COMMAND_SEND_UNSEQUENCED         = 9
 #ENET_PROTOCOL_COMMAND_BANDWIDTH_LIMIT          = 10
 #ENET_PROTOCOL_COMMAND_THROTTLE_CONFIGURE       = 11
 #ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE_FRAGMENT = 12
 #ENET_PROTOCOL_COMMAND_COUNT                    = 13
 #ENET_PROTOCOL_COMMAND_MASK                     = $F
 #ENET_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE = (1 << 7)
 #ENET_PROTOCOL_COMMAND_FLAG_UNSEQUENCED = (1 << 6)
 #ENET_PROTOCOL_HEADER_FLAG_COMPRESSED   = (1 << 14)
 #ENET_PROTOCOL_HEADER_FLAG_SENT_TIME    = (1 << 15)
 #ENET_PROTOCOL_HEADER_FLAG_MASK         = #ENET_PROTOCOL_HEADER_FLAG_COMPRESSED | #ENET_PROTOCOL_HEADER_FLAG_SENT_TIME
 #ENET_PROTOCOL_HEADER_SESSION_MASK      = (3 << 12)
 #ENET_PROTOCOL_HEADER_SESSION_SHIFT     = 12
 #ENET_PEER_UNSEQUENCED_WINDOW_SIZE      = 1024
 #ENET_SOCKET_TYPE_STREAM   = 1
 #ENET_SOCKET_TYPE_DATAGRAM = 2
 #ENET_SOCKET_WAIT_NONE      = 0
 #ENET_SOCKET_WAIT_SEND      = (1 << 0)
 #ENET_SOCKET_WAIT_RECEIVE   = (1 << 1)
 #ENET_SOCKET_WAIT_INTERRUPT = (1 << 2)
 #ENET_SOCKOPT_NONBLOCK  = 1
 #ENET_SOCKOPT_BROADCAST = 2
 #ENET_SOCKOPT_RCVBUF    = 3
 #ENET_SOCKOPT_SNDBUF    = 4
 #ENET_SOCKOPT_REUSEADDR = 5
 #ENET_SOCKOPT_RCVTIMEO  = 6
 #ENET_SOCKOPT_SNDTIMEO  = 7
 #ENET_SOCKOPT_ERROR     = 8
 #ENET_SOCKOPT_NODELAY   = 9
 #ENET_SOCKOPT_IPV6_V6ONLY = 10
 #ENET_SOCKET_SHUTDOWN_READ       = 0
 #ENET_SOCKET_SHUTDOWN_WRITE      = 1
 #ENET_SOCKET_SHUTDOWN_READ_WRITE = 2
 #ENET_PACKET_FLAG_RELIABLE            = (1 << 0);, /** packet must be received by the target peer And resend attempts should be made Until the packet is delivered */
 #ENET_PACKET_FLAG_UNSEQUENCED         = (1 << 1);, /** packet will Not be sequenced With other packets Not supported For reliable packets */
 #ENET_PACKET_FLAG_NO_ALLOCATE         = (1 << 2);, /** packet will Not allocate Data, And user must supply it instead */
 #ENET_PACKET_FLAG_UNRELIABLE_FRAGMENT = (1 << 3);, /** packet will be fragmented using unreliable (instead of reliable) sends If it exceeds the MTU */
 #ENET_PACKET_FLAG_SENT                = (1 << 8);, /** whether the packet has been sent from all queues it has been entered into */
 
 #ENET_PEER_STATE_DISCONNECTED             = 0
 #ENET_PEER_STATE_CONNECTING               = 1
 #ENET_PEER_STATE_ACKNOWLEDGING_CONNECT    = 2
 #ENET_PEER_STATE_CONNECTION_PENDING       = 3
 #ENET_PEER_STATE_CONNECTION_SUCCEEDED     = 4
 #ENET_PEER_STATE_CONNECTED                = 5
 #ENET_PEER_STATE_DISCONNECT_LATER         = 6
 #ENET_PEER_STATE_DISCONNECTING            = 7
 #ENET_PEER_STATE_ACKNOWLEDGING_DISCONNECT = 8
 #ENET_PEER_STATE_ZOMBIE                   = 9
 
 #ENET_HOST_RECEIVE_BUFFER_SIZE          = 256 * 1024
 #ENET_HOST_SEND_BUFFER_SIZE             = 256 * 1024
 #ENET_HOST_BANDWIDTH_THROTTLE_INTERVAL  = 1000
 #ENET_HOST_DEFAULT_MTU                  = 1400
 #ENET_HOST_DEFAULT_MAXIMUM_PACKET_SIZE  = 32 * 1024 * 1024
 #ENET_HOST_DEFAULT_MAXIMUM_WAITING_DATA = 32 * 1024 * 1024
 
 #ENET_PEER_DEFAULT_ROUND_TRIP_TIME      = 500
 #ENET_PEER_DEFAULT_PACKET_THROTTLE      = 32
 #ENET_PEER_PACKET_THROTTLE_SCALE        = 32
 #ENET_PEER_PACKET_THROTTLE_COUNTER      = 7
 #ENET_PEER_PACKET_THROTTLE_ACCELERATION = 2
 #ENET_PEER_PACKET_THROTTLE_DECELERATION = 2
 #ENET_PEER_PACKET_THROTTLE_INTERVAL     = 5000
 #ENET_PEER_PACKET_LOSS_SCALE            = (1 << 16)
 #ENET_PEER_PACKET_LOSS_INTERVAL         = 10000
 #ENET_PEER_WINDOW_SIZE_SCALE            = 64 * 1024
 #ENET_PEER_TIMEOUT_LIMIT                = 32
 #ENET_PEER_TIMEOUT_MINIMUM              = 5000
 #ENET_PEER_TIMEOUT_MAXIMUM              = 30000
 #ENET_PEER_PING_INTERVAL                = 500
 #ENET_PEER_UNSEQUENCED_WINDOWS          = 64
 #ENET_PEER_UNSEQUENCED_WINDOW_SIZE      = 1024
 #ENET_PEER_FREE_UNSEQUENCED_WINDOWS     = 32
 #ENET_PEER_RELIABLE_WINDOWS             = 16
 #ENET_PEER_RELIABLE_WINDOW_SIZE         = $1000
 #ENET_PEER_FREE_RELIABLE_WINDOWS        = 8
 
 #ENET_EVENT_TYPE_NONE       = 0
 #ENET_EVENT_TYPE_CONNECT    = 1
 #ENET_EVENT_TYPE_DISCONNECT = 2
 #ENET_EVENT_TYPE_RECEIVE    = 3
 #ENET_EVENT_TYPE_DISCONNECT_TIMEOUT = 4
 
 #ENET_BUFFER_MAXIMUM = (1 + 2 * #ENET_PROTOCOL_MAXIMUM_PACKET_COMMANDS)
  
 Structure ENetListNode 
   *Next.ENetListNode 
   *previous.ENetListNode ;
 EndStructure
 
 Structure ENetList 
   sentinel.ENetListNode;
 EndStructure
 
 PrototypeC  pENetPacketFreeCallback(*mem);
  
 Structure ENetPacket 
   referenceCount.i; /**< internal use only */
   flags.l         ;          /**< bitwise-or of ENetPacketFlag constants */
   *data           ;           /**< allocated data for packet */
   dataLength.l    ;     /**< length of data */
   freeCallback.pENetPacketFreeCallback;   /**< function to be called when the packet is no longer in use */
   *userData                           ;       /**< application private data, may be freely modified */
 EndStructure
 
 Structure ENetAcknowledgement
   acknowledgementList.ENetListNode  
   sentTime.l;
   command.i ;
 EndStructure
 
 Structure ENetOutgoingCommand
   outgoingCommandList.ENetListNode;
   reliableSequenceNumber.u        ;
   unreliableSequenceNumber.u      ;
   sentTime.l                      ;
   roundTripTimeout.l              ;
   roundTripTimeoutLimit.l         ;
   fragmentOffset.l                ;
   fragmentLength.u                ;
   sendAttempts.u                  ;
   command.i                       ;
   *packet.ENetPacket              ;
 EndStructure
 
 Structure ENetIncomingCommand 
   incomingCommandList.ENetListNode;
   reliableSequenceNumber.u        ;
   unreliableSequenceNumber.u      ;
   command.i                       ;
   fragmentCount.u                 ;
   fragmentsRemaining.u            ;
   *fragments                    ;
   *packet.ENetPacket              ;
 EndStructure
 
 Structure in6_addr
   l.q
   h.q
 EndStructure   
 
Structure ENetAddress
   host.in6_addr;
   port.u;
   sin6_scope_id.u;
EndStructure 

Structure ENetChannel 
  outgoingReliableSequenceNumber.u;
  outgoingUnreliableSequenceNumber.u;
  usedReliableWindows.u             ;
  reliableWindows.u[#ENET_PEER_RELIABLE_WINDOWS];
  incomingReliableSequenceNumber.u              ;
  incomingUnreliableSequenceNumber.u            ;
  incomingReliableCommands.ENetList             ;
  incomingUnreliableCommands.ENetList           ;
EndStructure

Structure ENetPeer 
  *dispatchList;
  *host.ENetHost;
  outgoingPeerID.u;
  incomingPeerID.u;
  connectID.l     ;
  outgoingSessionID.a;
  incomingSessionID.a;
  address.ENetAddress; /**< Internet address of the peer */
  *Data              ;    /**< Application private data, may be freely modified */
  state.i              ;
  *channels          ;
  channelCount.i     ;      /**< Number of channels allocated for communication with peer */
  incomingBandwidth.l; /**< Downstream bandwidth of the client in bytes/second */
  outgoingBandwidth.l; /**< Upstream bandwidth of the client in bytes/second */
  incomingBandwidthThrottleEpoch.l;
  outgoingBandwidthThrottleEpoch.l;
  incomingDataTotal.l             ;
  totalDataReceived.q             ;
  outgoingDataTotal.l             ;
  totalDataSent.q                 ;
  lastSendTime.l                  ;
  lastReceiveTime.l               ;
  nextTimeout.l                   ;
  earliestTimeout.l               ;
  packetLossEpoch.l               ;
  packetsSent.l                   ;
  totalPacketsSent.q              ; /**< total number of packets sent during a session */
  packetsLost.l                   ;
  totalPacketsLost.l              ;     /**< total number of packets lost during a session */
  packetLoss.l                    ; /**< mean packet loss of reliable packets as a ratio with respect to the constant ENET_PEER_PACKET_LOSS_SCALE */
  packetLossVariance.l            ;
  packetThrottle.l                ;
  packetThrottleLimit.l           ;
  packetThrottleCounter.l         ;
  packetThrottleEpoch.l           ;
  packetThrottleAcceleration.l    ;
  packetThrottleDeceleration.l    ;
  packetThrottleInterval.l        ;
  pingInterval.l                  ;
  timeoutLimit.l                  ;
  timeoutMinimum.l                ;
  timeoutMaximum.l                ;
  lastRoundTripTime.l             ;
  lowestRoundTripTime.l           ;
  lastRoundTripTimeVariance.l     ;
  highestRoundTripTimeVariance.l  ;
  roundTripTime.l                 ; /**< mean round trip time (RTT), in milliseconds, between sending a reliable packet and receiving its acknowledgement */
  roundTripTimeVariance.l         ;
  mtu.l                           ;
  windowSize.l                    ;
  reliableDataInTransit.l         ;
  outgoingReliableSequenceNumber.u;
  acknowledgements.ENetList       ;
  sentReliableCommands.ENetList   ;
  sentUnreliableCommands.ENetList ;
  outgoingReliableCommands.ENetList;
  outgoingUnreliableCommands.ENetList;
  dispatchedCommands.ENetList        ;
  needsDispatch.l                    ;
  incomingUnsequencedGroup.u         ;
  outgoingUnsequencedGroup.u         ;
  unsequencedWindow.l[#ENET_PEER_UNSEQUENCED_WINDOW_SIZE / 32];
  eventData.l                                                 ;
  totalWaitingData.i                                          ;
EndStructure  

PrototypeC pcompress(*context,*inBuffers,inBufferCount.i,inLimit.i,*outData,outLimit.l);
PrototypeC pdecompress(*context,*inData,inLimit.i,*outData,outLimit.i)                 ;
PrototypeC pDestroy(*context)                                                          ; 
                                                                                       
Structure ENetCompressor
  *context;
  *compress.pcompress
  *decompress.pdecompress 
  *destroy.pDestroy
EndStructure  

PrototypeC ENetChecksumCallback(*buffers,bufferCount.i);
PrototypeC ENetInterceptCallback(*host,*event);


Structure  ENetHost 
  socket.i;
  address.ENetAddress;           /**< Internet address of the host */
  incomingBandwidth.l;           /**< downstream bandwidth of the host */
  outgoingBandwidth.l;           /**< upstream bandwidth of the host */
  bandwidthThrottleEpoch.l
  mtu.l                   
  randomSeed.l            
  recalculateBandwidthLimits.l
  *peers.ENetPeer             ;   /**< array of peers allocated for this host */
  peerCount.i                 ;   /**< number of peers allocated for this host */
  channelLimit.i              ;   /**< maximum number of channels allowed for connected peers */
  serviceTime.u               
  dispatchQueue.ENetList      
  continueSending.l           
  packetSize.i                
  headerFlags.u               
  commands.i[#ENET_PROTOCOL_MAXIMUM_PACKET_COMMANDS]
  commandCount.i                                    
  buffers.i[#ENET_BUFFER_MAXIMUM]                   
  bufferCount.i                                     
  *checksum                                         ; ENetChecksumCallback /**< callback the user can set to enable packet checksums for this host */
  *compressor                                       ; ENetCompressor;
  packetData.a[#ENET_PROTOCOL_MAXIMUM_MTU*2]        ;;<<<<possibl problem [2][ENET_PROTOCOL_MAXIMUM_MTU]
  receivedAddress.ENetAddress                       
  *receivedData                                     
  receivedDataLength.i                              
  totalSentData.l                                   ;/**< total Data sent, user should reset To 0 As needed To prevent overflow */
  totalSentPackets.l                                ;/**< total UDP packets sent, user should reset to 0 as needed to prevent overflow */
  totalReceivedData.l                               ;/**< total data received, user should reset to 0 as needed to prevent overflow */
  totalReceivedPackets.l                            ;/**< total UDP packets received, user should reset to 0 as needed to prevent overflow */
  *intercept.ENetInterceptCallback                  ;/**< callback the user can set To intercept received raw UDP packets */
  connectedPeers.i                                  
  bandwidthLimitedPeers.i                           
  duplicatePeers.i                                  ;/**< optional number of allowed peers from duplicate IPs, defaults to ENET_PROTOCOL_MAXIMUM_PEER_ID */
  maximumPacketSize.i                               ;/**< the maximum allowable packet size that may be sent or received on a peer */
  maximumWaitingData.i                              ;/**< the maximum aggregate amount of buffer space a peer may use waiting for packets to be delivered */
EndStructure

Structure ENetEvent 
  type.i;                    ;/**< type of the event */
  *peer.ENetPeer             ;/**< peer that generated a connect, disconnect or receive event */
  channelID.a                ; /**< channel on the peer that generated the event, if appropriate */
  lData.l                    ;/**< data associated with the event, if appropriate */
  *packet.ENetPacket         ;/**< packet associated with the event, if appropriate */
EndStructure

ImportC "libenet_shared.dll.a" 
  enet_initialize()
  enet_initialize_with_callbacks(version.l,*inits.ENetCallbacks);
  enet_deinitialize()
  enet_linked_version()
  enet_time_get()
  enet_socket_create(ENetSocketType.i)
  enet_socket_bind(ENetSocket,*ENetAddress)
  enet_socket_get_address(ENetSocket,*ENetAddress)
  enet_socket_listen(ENetSocket,v.l)               
  enet_socket_accept(ENetSocket, *ENetAddress)     
  enet_socket_connect(ENetSocket,*ENetAddress)
  enet_socket_send(ENetSocket, *eNetAddress,*ENetBuffer,sz.i)
  enet_socket_receive(ENetSocket, *ENetAddress, *ENetBuffer,sz.i)         
  enet_socket_wait(ENetSocket,*enet,enet_uint64.q)                     
  enet_socket_set_option(ENetSocket, ENetSocketOption, int.l)                    
  enet_socket_get_option(ENetSocket, ENetSocketOption, *int)      
  enet_socket_shutdown(ENetSocket, ENetSocketShutdown)                         
  enet_socket_destroy(ENetSocket)                                              
  enet_socketset_select(ENetSocket, *ENetSocketSet , *ENetSocketSet1,enet_uint32.l)
  enet_address_set_host_ip_old(*address.ENetAddress,hostName.p-utf8)      
  enet_address_set_host_old(*address.ENetAddress,hostName.p-utf8)          
  enet_address_get_host_ip_old(*address.ENetAddress, hostName.p-utf8,nameLength.i)
  enet_address_get_host_old(*address.ENetAddress,hostName.p-utf8,nameLength.i)   
  enet_address_set_host_ip_new(*address.ENetAddress, hostName.p-utf8)                   
  enet_address_set_host_new(*address.ENetAddress,hostName.p-utf8)                      
  enet_address_get_host_ip_new(*address.ENetAddress,hostName.p-utf8,nameLength.i)
  enet_address_get_host_new(*address.ENetAddress,hostName.p-utf8,nameLength.i)   
  
  enet_host_get_peers_count(*ENetHost)
  enet_host_get_packets_sent(*ENetHost)
  enet_host_get_packets_received(*ENetHost)
  enet_host_get_bytes_sent(*ENetHost )      
  enet_host_get_bytes_received(*ENetHost )  
  enet_host_get_received_data(*ENetHost , *data)
  enet_host_get_mtu(*ENetHost)                            
  
  enet_peer_get_id(*ENetPeer )
  enet_peer_get_ip(*ENetPeer, *ip,ipLength.i)
  enet_peer_get_port(*ENetPeer )                          
  enet_peer_get_rtt(*ENetPeer )                           
  enet_peer_get_packets_sent(*ENetPeer )                  
  enet_peer_get_packets_lost(*ENetPeer )                  
  enet_peer_get_bytes_sent(*ENetPeer )                    
  enet_peer_get_bytes_received(*ENetPeer )                
  
  eet_peer_get_state(*ENetPeer )
  
  enet_peer_get_data(*ENetPeer )
  enet_peer_set_data(*ENetPeer , *data)
  
  enet_packet_get_data(*ENetPacket )
  enet_packet_get_length(*ENetPacket )
  enet_packet_set_free_callback(*ENetPacket , *mem)
  
  enet_packet_create_offset(*data,datalength.i,dataoffset.i,flags.l)
  enet_crc32(*buffer,sz.i)                              
  
  enet_host_create(*ENetAddress.ENetAddress,peercount.i,channelLimit.i,incomingBandwidth.l,outgoingBandwidth.l)
  enet_host_destroy(*ENetHost )                                                  
  enet_host_connect(*ENetHost,*address.ENetAddress,channelCount.i,udata.l)        
  enet_host_check_events(*ENetHost , *ENetEvent )                                
  enet_host_service(*ENetHost ,*ENetEvent ,timeout.l)                            
  enet_host_send_raw(*ENetHost ,*address.ENetAddress, *data, bytestosend.i)      
  enet_host_send_raw_ex(*ENetHost,*address.ENetAddress,*Data,skipBytes.i,bytesToSend.i)
  enet_host_set_intercept(*ENetHost,*cb.ENetInterceptCallback)                                                         
  enet_host_flush(*ENetHost )                                                                                              
  enet_host_broadcast(*ENetHost,channelID.a,*ENetPacket)                                                                    
  enet_host_compress(*ENetHost ,*ENetCompressor)                                                                   
  enet_host_channel_limit(*ENetHost, channelLimit.i)                                                                              
  enet_host_bandwidth_limit(*ENetHost, incomminglimit.i,outgoinglimit.i)                                                          
  enet_host_bandwidth_throttle(*ENetHost )                                                                                 
  enet_host_random_seed(void)                                                                                              
  
  enet_peer_send(*ENetPeer, channelID.a, *ENetPacket)
  enet_peer_receive(*ENetPeer ,*channelID)
  enet_peer_ping(*ENetPeer )                           
  enet_peer_ping_interval(*ENetPeer , interval.l)     
  enet_peer_timeout(*ENetPeer , timeoutLimit.l, timeoutMinimum.l, timeoutMaximum.l)
  enet_peer_reset(*ENetPeer )                                         
  enet_peer_disconnect(*ENetPeer , udata.l)                       
  enet_peer_disconnect_now(*ENetPeer ,udata.l)                   
  enet_peer_disconnect_later(*ENetPeer , udata.l)                 
  enet_peer_throttle_configure(*ENetPeer, interval.l, acceleration.l, deceleration.l)
  enet_peer_throttle(*ENetPeer ,rtt.l)                                    
  enet_peer_reset_queues(*ENetPeer )                                             
  enet_peer_setup_outgoing_command(*ENetPeer , *ENetOutgoingCommand )            
  
  enet_peer_queue_outgoing_command(*ENetPeer ,*ENetProtocol, *ENetPacket , offset.l, length.u)
  enet_peer_queue_incoming_command(*ENetPeer ,*ENetProtocol, *data, dataLength.l, flags.l, fragmentCount.l)
  
  enet_peer_queue_acknowledgement(*ENetPeer ,*ENetProtocol, sentTime.u)                                    
  
  enet_peer_dispatch_incoming_unreliable_commands(*ENetPeer ,*ENetChannel)                                        
  enet_peer_dispatch_incoming_reliable_commands(*ENetPeer , *ENetChannel )                                          
  
  enet_peer_on_connect(*ENetPeer )                                                                                  
  enet_peer_on_disconnect(*ENetPeer )                                                                               
  
  enet_protocol_command_size(sz.a)
EndImport 

Macro ENET_VERSION_GET_MAJOR(version)
  (((version)>>16)&$FF)
EndMacro
Macro ENET_VERSION_GET_MINOR(version)
  (((version)>>8)&$FF) 
EndMacro
Macro ENET_VERSION_GET_PATCH(version)
  ((version)&$FF)
EndMacro 

CompilerIf #PB_Compiler_IsMainFile 
  
  Define version 
    
  enet_initialize()
  
  version = enet_linked_version()
  Debug ENET_VERSION_GET_MAJOR(version)
  Debug ENET_VERSION_GET_MINOR(version)
  Debug ENET_VERSION_GET_PATCH(version)  
  
  enet_deinitialize()
  
CompilerEndIf   
  