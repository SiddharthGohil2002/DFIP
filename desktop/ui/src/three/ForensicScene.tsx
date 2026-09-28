import {Canvas,useFrame} from '@react-three/fiber';
import {Float,Line,OrbitControls,Stars,Text} from '@react-three/drei';
import {useRef} from 'react';
import * as THREE from 'three';

function Core(){
  const ref=useRef<THREE.Mesh>(null!);
  useFrame((_state,delta)=>{ref.current.rotation.x+=delta*.15;ref.current.rotation.y+=delta*.25});
  return(
    <mesh ref={ref}>
      <icosahedronGeometry args={[1.35,2]}/>
      <meshStandardMaterial color="#C8102E" wireframe emissive="#7a0a1a" emissiveIntensity={1.2}/>
    </mesh>
  );
}

interface NodeProps{p:[number,number,number];label:string}
function Node({p,label}:NodeProps){
  const ref=useRef<THREE.Mesh>(null!);
  useFrame((_state,delta)=>{ref.current.rotation.y+=delta*.5});
  return(
    <Float speed={1.2} rotationIntensity={.2} floatIntensity={.5}>
      <mesh ref={ref} position={p}>
        <sphereGeometry args={[.12,16,16]}/>
        <meshStandardMaterial color="#ff6b6b" emissive="#7a0000" emissiveIntensity={1.8}/>
        <Text position={[0,.25,0]} fontSize={.12} color="#1A1F29" anchorX="center">{label}</Text>
      </mesh>
    </Float>
  );
}

const NODES:[number,number,number,string][]=[
  [-2,1,0,'EVIDENCE'],[2,1,0,'FILES'],
  [-2,-1,0,'TIMELINE'],[2,-1,0,'ANALYSIS'],
  [0,2,0,'USB'],[0,-2,0,'REPORT']
];

export default function ForensicScene(){
  return(
    <div className="scene">
      <Canvas camera={{position:[0,0,7],fov:45}} dpr={[1,1.6]}>
        <ambientLight intensity={.8}/>
        <pointLight position={[3,3,4]} intensity={8} color="#ff6b6b"/>
        <Stars radius={20} depth={8} count={800} factor={2} saturation={0}/>
        <Core/>
        {NODES.map(([x,y,z,l])=>(
          <Node key={l} p={[x,y,z] as [number,number,number]} label={l}/>
        ))}
        {NODES.map(([x,y,z,l])=>(
          <Line key={`ln-${l}`} points={[[0,0,0],[x,y,z]]} color="#C8102E" transparent opacity={.4} lineWidth={1}/>
        ))}
        <OrbitControls enableZoom={false} autoRotate autoRotateSpeed={.3}/>
      </Canvas>
    </div>
  );
}
