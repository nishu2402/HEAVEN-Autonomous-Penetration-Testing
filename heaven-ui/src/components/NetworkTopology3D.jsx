import { useRef, useMemo, useState } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { OrbitControls, Html, Stars } from '@react-three/drei'
import * as THREE from 'three'

// three.js materials need real hex colors (CSS vars can't reach the GPU),
// so the premium palette is mirrored here as literals.
const SEV_COLORS = {
  critical: '#FF4D6A', high: '#FF8A3D', medium: '#FFC53D',
  low: '#38BDF8', info: '#8593AD', unknown: '#6D7CFF',
}
const ACCENT = '#6D7CFF'
const ACCENT_2 = '#A78BFA'

// Highest-risk hosts win the limited node budget so a wide /24 sweep never
// floods the view with dozens of low-signal spheres.
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 }
const MAX_NODES = 24              // cap; larger scans show "+N more"
const GOLDEN_ANGLE = Math.PI * (3 - Math.sqrt(5))  // ~137.5° — even, no clumping

function hostSeverity(h) {
  return h.severity || h.max_severity || 'unknown'
}

function Edge({ start, end, color }) {
  const ref = useRef()
  const points = useMemo(() => [
    new THREE.Vector3(...start),
    new THREE.Vector3(...end),
  ], [start, end])
  const geo = useMemo(() => new THREE.BufferGeometry().setFromPoints(points), [points])

  useFrame(({ clock }) => {
    if (ref.current) {
      ref.current.material.opacity = 0.09 + 0.05 * Math.sin(clock.elapsedTime * 1.5 + start[0])
    }
  })

  return (
    <line ref={ref} geometry={geo}>
      <lineBasicMaterial color={color || ACCENT} transparent opacity={0.14} />
    </line>
  )
}

function HostNode({ host, position, severity, portCount, sizeScale, onClick }) {
  const mesh = useRef()
  const ring = useRef()
  const [hovered, setHovered] = useState(false)
  const color = SEV_COLORS[severity] || SEV_COLORS.unknown
  const radius = (0.12 + Math.min(portCount * 0.025, 0.35)) * sizeScale

  useFrame(({ clock }) => {
    if (!mesh.current) return
    const t = clock.elapsedTime
    mesh.current.position.y = position[1] + Math.sin(t * 0.7 + position[0] * 2) * 0.05
    mesh.current.rotation.y = t * 0.3
    if (ring.current) {
      ring.current.rotation.z = t * 0.5
      ring.current.scale.setScalar(hovered ? 1.3 : 1.0)
    }
  })

  return (
    <group>
      <mesh
        ref={mesh}
        position={position}
        onPointerOver={() => setHovered(true)}
        onPointerOut={() => setHovered(false)}
        onClick={() => onClick && onClick(host)}
      >
        <icosahedronGeometry args={[radius, 1]} />
        <meshStandardMaterial
          color={color} emissive={color}
          emissiveIntensity={hovered ? 0.9 : 0.35}
          transparent opacity={0.9}
          wireframe={hovered}
        />
      </mesh>

      <mesh ref={ring} position={position} rotation={[Math.PI / 2, 0, 0]}>
        <torusGeometry args={[radius * 1.6, 0.012, 8, 32]} />
        <meshBasicMaterial color={color} transparent opacity={hovered ? 0.7 : 0.22} />
      </mesh>

      {hovered && (
        <Html position={[position[0], position[1] + radius + 0.3, position[2]]}
              style={{ pointerEvents: 'none' }}>
          <div style={{
            background: 'rgba(11,15,26,0.94)',
            border: `1px solid ${color}`,
            borderRadius: 8,
            color: '#ECEFF7',
            padding: '7px 11px',
            fontSize: '11px',
            fontFamily: 'JetBrains Mono, monospace',
            whiteSpace: 'nowrap',
            boxShadow: `0 8px 24px rgba(0,0,0,0.5), 0 0 16px ${color}55`,
          }}>
            <div style={{ color, fontWeight: 700 }}>{host.ip || host.host || 'unknown'}</div>
            <div style={{ color: '#9BA7C0', fontSize: 10, marginTop: 2 }}>
              {severity?.toUpperCase()} · {portCount} port{portCount !== 1 ? 's' : ''}
            </div>
          </div>
        </Html>
      )}
    </group>
  )
}

function GridPlane() {
  return (
    <gridHelper args={[20, 20, '#1b2336', '#141a28']} position={[0, -2, 0]} />
  )
}

function Scene({ hosts, onSelect }) {
  // Key the layout on the actual host identities, not just the count — switching
  // to another engagement with the same number of hosts (but different IPs) must
  // still relayout so the topology reflects the engagement you're viewing.
  const hostKey = hosts.map((h) => h.ip || h.host || '?').join('|')

  // Deterministic phyllotaxis (sunflower) spread: evenly area-filling, never
  // overlapping, and — crucially — stable across re-renders. The previous layout
  // used Math.random() for height + random cross-links, which read as a jittery,
  // tangled mess. Height is a fixed 3-tier band by index for depth without chaos.
  const positions = useMemo(() => {
    const n = hosts.length
    const spacing = n > 12 ? 0.62 : 0.78   // spread out a touch more when denser
    return hosts.map((_, i) => {
      const r = spacing * Math.sqrt(i + 0.5)
      const angle = i * GOLDEN_ANGLE
      const tier = (i % 3) - 1              // -1, 0, +1
      return [Math.cos(angle) * r, tier * 0.5, Math.sin(angle) * r]
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hostKey])

  // Clean edges: link each node only to its single nearest neighbour (deduped),
  // yielding a sparse, readable web instead of the old random criss-cross.
  const edges = useMemo(() => {
    const out = []
    const seen = new Set()
    for (let i = 0; i < positions.length; i++) {
      let best = -1
      let bestD = Infinity
      for (let j = 0; j < positions.length; j++) {
        if (i === j) continue
        const dx = positions[i][0] - positions[j][0]
        const dy = positions[i][1] - positions[j][1]
        const dz = positions[i][2] - positions[j][2]
        const d = dx * dx + dy * dy + dz * dz
        if (d < bestD) { bestD = d; best = j }
      }
      if (best >= 0) {
        const key = i < best ? `${i}-${best}` : `${best}-${i}`
        if (!seen.has(key)) {
          seen.add(key)
          out.push({ start: positions[i], end: positions[best] })
        }
      }
    }
    return out
  }, [positions])

  // Shrink nodes as the count climbs so a busy map stays legible.
  const sizeScale = Math.max(0.55, Math.min(1, 1 - hosts.length / 60))

  return (
    <>
      <ambientLight intensity={0.12} />
      <pointLight position={[0, 5, 0]} intensity={0.6} color={ACCENT} />
      <pointLight position={[-5, -2, -5]} intensity={0.35} color={ACCENT_2} />
      <Stars radius={30} depth={20} count={300} factor={2} saturation={0} fade speed={0.5} />
      <GridPlane />
      {edges.map((e, i) => (
        <Edge key={i} start={e.start} end={e.end} />
      ))}
      {hosts.map((host, i) => (
        <HostNode
          key={host.ip || host.host || i}
          host={host}
          position={positions[i]}
          severity={hostSeverity(host)}
          portCount={host.open_ports?.length || 1}
          sizeScale={sizeScale}
          onClick={onSelect}
        />
      ))}
      <OrbitControls
        enableZoom={true} enablePan={false}
        minDistance={3} maxDistance={15}
        autoRotate autoRotateSpeed={0.4}
        makeDefault
      />
    </>
  )
}

export default function NetworkTopology3D({ hosts = [] }) {
  const [selected, setSelected] = useState(null)

  // Rank by severity (then port count) and cap so large scans stay readable.
  const { shown, hiddenCount, total } = useMemo(() => {
    const sorted = [...hosts].sort((a, b) => {
      const sa = SEV_RANK[hostSeverity(a)] ?? 9
      const sb = SEV_RANK[hostSeverity(b)] ?? 9
      if (sa !== sb) return sa - sb
      return (b.open_ports?.length || 0) - (a.open_ports?.length || 0)
    })
    return {
      shown: sorted.slice(0, MAX_NODES),
      hiddenCount: Math.max(0, sorted.length - MAX_NODES),
      total: hosts.length,
    }
  }, [hosts])

  const hasHosts = total > 0
  const capped = hiddenCount > 0

  return (
    <div className="topology-container">
      <div style={{
        position: 'absolute', top: 12, right: 14, zIndex: 10, textAlign: 'right',
        fontSize: 11, color: 'var(--text-2)', letterSpacing: '0.06em',
      }}>
        {!hasHosts && <span style={{ textTransform: 'uppercase' }}>○ no hosts — run a scan</span>}
        {hasHosts && !capped && (
          <><span style={{ color: 'var(--brand)' }}>●</span> {total} host{total !== 1 ? 's' : ''} mapped</>
        )}
        {hasHosts && capped && (
          <>
            <div><span style={{ color: 'var(--brand)' }}>●</span> top {shown.length} of {total} hosts</div>
            <div style={{ fontSize: 10, color: 'var(--text-3, var(--text-2))', marginTop: 2 }}>
              +{hiddenCount} more · ranked by severity
            </div>
          </>
        )}
      </div>

      <Canvas
        camera={{ position: [0, 2, 8], fov: 55 }}
        gl={{ antialias: true, alpha: true }}
        style={{ background: 'transparent' }}
      >
        <Scene hosts={shown} onSelect={setSelected} />
      </Canvas>

      {selected && (
        <div className="card-glass" style={{
          position: 'absolute', bottom: 14, left: 14, right: 14,
          padding: '10px 14px', borderRadius: 'var(--radius-md)',
          fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text-0)',
          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        }}>
          <span>
            <span style={{ color: SEV_COLORS[hostSeverity(selected)] }}>●</span>
            {' '}{selected.ip || selected.host}
            {' · '}{selected.open_ports?.join(', ') || '—'}
          </span>
          <button
            onClick={() => setSelected(null)}
            style={{ background: 'none', border: 'none', color: 'var(--text-2)', cursor: 'pointer', fontSize: 14 }}
          >✕</button>
        </div>
      )}

      <div className="topology-legend">
        {Object.entries(SEV_COLORS).slice(0, 5).map(([sev, col]) => (
          <span key={sev}>
            <span className="legend-dot" style={{ background: col }} />
            {sev}
          </span>
        ))}
      </div>
    </div>
  )
}
