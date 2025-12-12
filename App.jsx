import { useState, useEffect } from 'react'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import { format, parseISO } from 'date-fns'

function App() {
  const [data, setData] = useState({
    summary: null,
    mitmEvents: [],
    suricataEvents: [],
    timeline: []
  })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [lastUpdate, setLastUpdate] = useState(null)

  const loadData = async () => {
    setLoading(true)
    setError(null)
    
    try {
      const [summaryRes, mitmRes, suricataRes, timelineRes] = await Promise.all([
        fetch('/data/summary.json'),
        fetch('/data/mitm_events.json'),
        fetch('/data/suricata_events.json'),
        fetch('/data/attack_timeline.csv')
      ])

      const summary = await summaryRes.json()
      const mitmEvents = await mitmRes.json()
      const suricataEvents = await suricataRes.json()
      const timelineText = await timelineRes.text()

      const timelineLines = timelineText.trim().split('\n').slice(1)
      const timeline = timelineLines.map(line => {
        const [timestamp, event] = line.split(',')
        return { timestamp, event }
      })

      setData({
        summary,
        mitmEvents,
        suricataEvents,
        timeline
      })
      setLastUpdate(new Date())
      setLoading(false)
    } catch (err) {
      setError('Failed to load data: ' + err.message)
      setLoading(false)
    }
  }

  useEffect(() => {
    loadData()
    const interval = setInterval(loadData, 10000)
    return () => clearInterval(interval)
  }, [])

  if (loading && !data.summary) {
    return (
      <div className="dashboard">
        <div className="loading">Loading dashboard data...</div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="dashboard">
        <div className="error">
          <h3>Error</h3>
          <p>{error}</p>
          <button onClick={loadData} className="refresh-button">Retry</button>
        </div>
      </div>
    )
  }

  const httpMethodData = data.mitmEvents
    .filter(e => e.type === 'http_request')
    .reduce((acc, e) => {
      const method = e.method || 'UNKNOWN'
      acc[method] = (acc[method] || 0) + 1
      return acc
    }, {})

  const methodChartData = Object.entries(httpMethodData).map(([method, count]) => ({
    method,
    count
  }))

  return (
    <div className="dashboard">
      <header className="header">
        <h1>MITM Cyber Range Dashboard</h1>
        <p>Real-time monitoring of man-in-the-middle attack simulation</p>
        {lastUpdate && (
          <p style={{ fontSize: '0.9em', color: '#999', marginTop: '10px' }}>
            Last updated: {format(lastUpdate, 'PPpp')}
          </p>
        )}
      </header>

      <button onClick={loadData} className="refresh-button" disabled={loading}>
        {loading ? 'Refreshing...' : 'Refresh Data'}
      </button>

      <div className="stats-grid">
        <div className="stat-card">
          <h3>Total HTTP Requests</h3>
          <div className="value">{data.summary?.total_http_requests || 0}</div>
        </div>
        <div className="stat-card">
          <h3>Total Connections</h3>
          <div className="value">{data.summary?.total_connections || 0}</div>
        </div>
        <div className="stat-card">
          <h3>Unique URLs</h3>
          <div className="value">{data.summary?.unique_urls || 0}</div>
        </div>
        <div className="stat-card">
          <h3>Suricata Events</h3>
          <div className="value">{data.summary?.total_suricata_events || 0}</div>
        </div>
      </div>

      <section className="section">
        <h2>Attack Timeline</h2>
        <div className="timeline">
          {data.timeline.length === 0 ? (
            <p>No attack events recorded yet</p>
          ) : (
            data.timeline.map((item, idx) => (
              <div key={idx} className={'timeline-item ' + item.event}>
                <span className="timeline-time">
                  {format(parseISO(item.timestamp), 'PPpp')}
                </span>
                <span className="timeline-event">
                  {item.event === 'start' ? 'Attack Started' : 'Attack Stopped'}
                </span>
              </div>
            ))
          )}
        </div>
      </section>

      {methodChartData.length > 0 && (
        <section className="section">
          <h2>HTTP Methods Distribution</h2>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={methodChartData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="method" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Bar dataKey="count" fill="#667eea" />
            </BarChart>
          </ResponsiveContainer>
        </section>
      )}

      <section className="section">
        <h2>Intercepted HTTP Requests</h2>
        <div className="events-list">
          {data.mitmEvents.filter(e => e.type === 'http_request').length === 0 ? (
            <p>No HTTP requests intercepted yet</p>
          ) : (
            data.mitmEvents
              .filter(e => e.type === 'http_request')
              .reverse()
              .map((event, idx) => (
                <div key={idx} className="event-item">
                  <div className="event-header">
                    <span className={'event-method ' + event.method}>
                      {event.method}
                    </span>
                    <span className="event-time">
                      {event.timestamp && format(parseISO(event.timestamp), 'HH:mm:ss')}
                    </span>
                  </div>
                  <div className="event-url">{event.url}</div>
                  <div className="event-meta">
                    <span>Client: {event.client_ip}</span>
                    {event.status_code && (
                      <span className={'status-code ' + (event.status_code < 400 ? 'success' : 'error')}>
                        Status: {event.status_code}
                      </span>
                    )}
                  </div>
                </div>
              ))
          )}
        </div>
      </section>

      <section className="section">
        <h2>Network Events (Suricata)</h2>
        <div className="events-list">
          {data.suricataEvents.length === 0 ? (
            <p>No Suricata events detected yet</p>
          ) : (
            data.suricataEvents
              .reverse()
              .map((event, idx) => (
                <div key={idx} className="event-item">
                  <div className="event-header">
                    <span style={{ fontWeight: 'bold', color: '#667eea' }}>
                      {event.event_type}
                    </span>
                    <span className="event-time">
                      {event.timestamp && format(parseISO(event.timestamp), 'HH:mm:ss')}
                    </span>
                  </div>
                  <div className="event-meta">
                    <span>{event.src_ip}:{event.src_port}</span>
                    <span>to</span>
                    <span>{event.dest_ip}:{event.dest_port}</span>
                    <span>Proto: {event.proto}</span>
                  </div>
                  {event.http_method && (
                    <div style={{ marginTop: '8px', color: '#666' }}>
                      {event.http_method} {event.http_url}
                    </div>
                  )}
                </div>
              ))
          )}
        </div>
      </section>
    </div>
  )
}

export default App