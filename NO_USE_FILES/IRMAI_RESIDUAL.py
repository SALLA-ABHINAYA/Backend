class AIGapAnalyzer:
    def __init__(self, api_key: str = None):
        """Initialize analyzer with OpenAI API key"""
        self.api_key = api_key or st.secrets.get("OPENAI_API_KEY")

        try:
            # Initialize OpenAI client
            self.client = get_azure_openai_client()
            logger.info("OpenAI client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI client: {str(e)}")
            raise

    def analyze_process_gaps(self, process_data: Dict, guidelines: Dict) -> Dict:
        """Use AI to analyze gaps between process and guidelines with error handling"""
        try:
            context = {
                "process_summary": {
                    "total_activities": len(process_data.get('activities', [])),
                    "total_events": process_data.get('total_events', 0),
                    "activities": [a['name'] for a in process_data.get('activities', [])]
                },
                "guidelines_summary": {
                    "total_guidelines": len(guidelines.get('guidelines', [])),
                    "guidelines": [g['name'] for g in guidelines.get('guidelines', [])]
                }
            }

            logger.debug(f"Analysis context: {context}")

            prompt = (
                "Analyze this process data and provide gaps, recommendations, and metrics in JSON format.\n"
                f"Context: {json.dumps(context, indent=2)}\n\n"
                "Response must be valid JSON with this structure:\n"
                "{\n"
                '  "gaps": [{"category": "string", "severity": "string", "description": "string"}],\n'
                '  "recommendations": [{"description": "string", "priority": "string"}],\n'
                '  "metrics": {"coverage": number, "effectiveness": number}\n'
                "}"
            )

            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a process mining expert. Always respond with valid JSON only."
                    },
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=1000
            )

            response_text = response.choices[0].message.content

            # Clean response text
            if "```json" in response_text:
                response_text = response_text.split("```json")[1].split("```")[0]
            elif "```" in response_text:
                response_text = response_text.split("```")[1]

            response_text = response_text.strip()

            try:
                analysis = json.loads(response_text)
                logger.info("Successfully parsed AI analysis")
                return analysis
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse AI response: {str(e)}")
                logger.error(f"Raw response: {response_text}")
                return self._get_default_analysis()

        except Exception as e:
            logger.error(f"Error in AI gap analysis: {str(e)}")
            logger.error(traceback.format_exc())
            return self._get_default_analysis()

    def _get_default_analysis(self) -> Dict:
        """Return default analysis structure when AI fails"""
        return {
            'gaps': [
                {
                    'category': 'Process Coverage',
                    'severity': 'Medium',
                    'description': 'Standard gap analysis based on process metrics'
                }
            ],
            'recommendations': [
                {
                    'description': 'Review process completion rates and controls',
                    'priority': 'High'
                }
            ],
            'metrics': {
                'coverage': 75.0,
                'effectiveness': 70.0
            }
        }
   
    def _structure_analysis(self, raw_analysis: Dict) -> Dict:
        """Structure and validate AI analysis output"""
        structured = {
            'gaps': [],
            'recommendations': [],
            'metrics': {
                'compliance': {},
                'operational': {},
                'risk': {}
            }
        }

        # Process identified gaps
        for gap in raw_analysis.get('gaps', []):
            structured['gaps'].append({
                'category': gap.get('category'),
                'description': gap.get('description'),
                'severity': gap.get('severity', 'Medium'),
                'impact': gap.get('impact'),
                'related_controls': gap.get('related_controls', [])
            })

        # Process recommendations
        for rec in raw_analysis.get('recommendations', []):
            structured['recommendations'].append({
                'description': rec.get('description'),
                'priority': rec.get('priority', 'Medium'),
                'implementation_timeline': rec.get('timeline'),
                'expected_impact': rec.get('expected_impact'),
                'required_resources': rec.get('required_resources', [])
            })

        # Process metrics
        metrics = raw_analysis.get('metrics', {})
        structured['metrics'] = {
            'compliance': {
                'regulatory_coverage': metrics.get('regulatory_coverage', 0),
                'control_effectiveness': metrics.get('control_effectiveness', 0)
            },
            'operational': {
                'process_adherence': metrics.get('process_adherence', 0),
                'efficiency_score': metrics.get('efficiency_score', 0)
            },
            'risk': {
                'risk_coverage': metrics.get('risk_coverage', 0),
                'control_maturity': metrics.get('control_maturity', 0)
            }
        }

        return structured

    def analyze_recommendations(self, gaps: List[Dict]) -> List[Dict]:
        """Use AI to generate detailed recommendations based on identified gaps"""
        try:
            context = f"""
            Based on these identified process gaps:
            {json.dumps(gaps, indent=2)}

            Generate detailed recommendations including:
            1. Immediate actions needed
            2. Long-term improvements
            3. Resource requirements
            4. Implementation timeline
            5. Expected benefits

            Format as structured JSON.
            """

            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are an expert process improvement consultant."},
                    {"role": "user", "content": context}
                ],
                temperature=0.7,
                max_tokens=1000
            )

            recommendations = json.loads(response.choices[0].message.content)
            return self._structure_recommendations(recommendations)

        except Exception as e:
            logging.error(f"Error generating AI recommendations: {str(e)}")
            raise

    def _structure_recommendations(self, raw_recommendations: List[Dict]) -> List[Dict]:
        """Structure and validate AI-generated recommendations"""
        structured = []
        for rec in raw_recommendations:
            structured.append({
                'id': f"REC_{len(structured) + 1:03d}",
                'description': rec.get('description'),
                'priority': rec.get('priority', 'Medium'),
                'target_date': rec.get('timeline'),
                'status': 'Open',
                'impact': rec.get('expected_benefits'),
                'resources': rec.get('required_resources', []),
                'implementation_steps': rec.get('implementation_steps', [])
            })
        return structured


class GapAnalysisVisualizer:
    """Visualization component for gap analysis results"""

    def __init__(self, report: Dict):
        self.report = report
        self.findings = pd.DataFrame(report.get('findings', []))
        self.metrics = pd.DataFrame.from_dict(report.get('metrics', {}), orient='index')
        self.logger = logging.getLogger(__name__)
        # Initialize OpenAI client
        self.client = get_azure_openai_client()

    def get_ai_explanation(self, data: Dict, chart_type: str) -> str:
        """Get AI explanation for a visualization"""
        try:
            chart_contexts = {
                'overview': """Analyze the overall process metrics and identify key patterns.""",
                'severity_distribution': """Analyze the distribution of gap severities and their implications.""",
                'coverage_radar': """Analyze the coverage metrics across different dimensions.""",
                'gap_heatmap': """Analyze the patterns and clusters in the gap distribution.""",
                'timeline_view': """Analyze the implementation timeline and priority distribution."""
            }

            base_prompt = f"""
            Analyze this {chart_type} data:
            {json.dumps(data, indent=2)}

            Context: {chart_contexts.get(chart_type, '')}

            Provide a concise 2-3 sentence analysis focusing on:
            1. Key patterns or trends
            2. Business implications
            3. Actionable insights

            Keep the explanation business-friendly and actionable.
            """

            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are a process analytics expert."},
                    {"role": "user", "content": base_prompt}
                ],
                temperature=0.7,
                max_tokens=150
            )

            return response.choices[0].message.content

        except Exception as e:
            self.logger.error(f"Error getting AI explanation: {str(e)}")
            return "AI analysis currently unavailable."

    def create_severity_distribution(self) -> Tuple[go.Figure, str]:
        """Create severity distribution chart with explanation"""
        summary = self.report.get('summary', {})

        fig = go.Figure(data=[
            go.Bar(
                name='Gaps',
                x=['High', 'Medium', 'Low'],
                y=[summary.get('high_severity', 0),
                   summary.get('medium_severity', 0),
                   summary.get('low_severity', 0)],
                marker_color=['#ff4d4d', '#ffa64d', '#4da6ff']
            )
        ])

        fig.update_layout(
            title='Gap Severity Distribution',
            xaxis_title='Severity Level',
            yaxis_title='Number of Gaps',
            template='plotly_white'
        )

        explanation = self.get_ai_explanation(summary, "severity distribution")
        return fig, explanation

    def create_coverage_radar(self) -> Tuple[go.Figure, str]:
        """Create coverage radar chart with explanation"""
        metrics = self.report.get('metrics', {})

        values = [
            round(metrics.get('compliance', {}).get('regulatory_coverage', 0), 1),
            round(metrics.get('operational', {}).get('process_adherence', 0), 1),
            round(metrics.get('risk', {}).get('control_coverage', 0), 1),
            round(metrics.get('risk', {}).get('risk_assessment_completion', 0), 1)
        ]

        categories = [
            'Regulatory Coverage',
            'Process Adherence',
            'Control Coverage',
            'Risk Assessment'
        ]

        fig = go.Figure(data=go.Scatterpolar(
            r=values,
            theta=categories,
            fill='toself',
            marker_color='rgb(77, 166, 255)'
        ))

        fig.update_layout(
            polar=dict(
                radialaxis=dict(
                    visible=True,
                    range=[0, 100],
                    ticksuffix='%'
                )
            ),
            showlegend=False,
            title='Coverage Analysis'
        )

        explanation = self.get_ai_explanation(metrics, "coverage metrics")
        return fig, explanation

    def create_gap_heatmap(self) -> Tuple[go.Figure, str]:
        """Create gap heatmap with explanation"""
        if len(self.findings) == 0:
            return go.Figure(), "No data available for heatmap analysis."

        heatmap_data = pd.crosstab(
            index=self.findings.get('category', 'Unknown'),
            columns=self.findings.get('severity', 'Medium')
        ).fillna(0)

        fig = go.Figure(data=go.Heatmap(
            z=heatmap_data.values,
            x=heatmap_data.columns,
            y=heatmap_data.index,
            colorscale='RdYlBu_r'
        ))

        fig.update_layout(
            title='Gap Distribution Heatmap',
            xaxis_title='Severity',
            yaxis_title='Category'
        )

        explanation = self.get_ai_explanation(
            heatmap_data.to_dict(),
            "gap distribution heatmap"
        )
        return fig, explanation

    def create_timeline_view(self) -> Tuple[go.Figure, str]:
        """Create timeline view with explanation"""
        recommendations = self.report.get('recommendations', [])

        if not recommendations:
            return go.Figure(), "No timeline data available."

        # Convert recommendations to DataFrame
        df = pd.DataFrame(recommendations)

        fig = go.Figure()

        for priority in ['High', 'Medium', 'Low']:
            mask = df['priority'] == priority
            if any(mask):
                fig.add_trace(go.Scatter(
                    x=pd.to_datetime(df[mask]['target_date']),
                    y=[priority] * sum(mask),
                    mode='markers+text',
                    name=priority,
                    text=df[mask]['description'],
                    marker=dict(
                        size=10,
                        symbol='circle'
                    )
                ))

        fig.update_layout(
            title='Recommendation Timeline',
            xaxis_title='Target Date',
            yaxis_title='Priority'
        )

        explanation = self.get_ai_explanation(
            {"recommendations": recommendations},
            "recommendation timeline"
        )
        return fig, explanation

    def generate_dashboard(self) -> Dict[str, Any]:
        """Generate complete dashboard with visualizations and AI explanations"""
        try:
            # Create visualizations
            severity_fig, severity_expl = self.create_severity_distribution()
            coverage_fig, coverage_expl = self.create_coverage_radar()
            heatmap_fig, heatmap_expl = self.create_gap_heatmap()
            timeline_fig, timeline_expl = self.create_timeline_view()

            # Generate overview explanation
            overview_data = {
                'total_gaps': self.report['summary']['total_gaps'],
                'high_severity': self.report['summary']['high_severity'],
                'coverage': self.report['metrics']['operational']['process_adherence'],
                'effectiveness': self.report['metrics']['risk']['control_coverage']
            }
            overview_expl = self.get_ai_explanation(overview_data, 'overview')

            return {
                'figures': {
                    'severity_distribution': severity_fig,
                    'coverage_radar': coverage_fig,
                    'gap_heatmap': heatmap_fig,
                    'timeline_view': timeline_fig
                },
                'explanations': {
                    'overview': overview_expl,
                    'severity_distribution': severity_expl,
                    'coverage_radar': coverage_expl,
                    'gap_heatmap': heatmap_expl,
                    'timeline_view': timeline_expl
                }
            }

        except Exception as e:
            self.logger.error(f"Error generating dashboard: {str(e)}")
            return {
                'figures': {},
                'explanations': {
                    'error': f"Error generating visualizations: {str(e)}"
                }
            }

    def display_recommendations_table(self) -> None:
        """Display recommendations table with error handling"""
        try:
            recommendations = self.report.get('recommendations', [])

            if not recommendations:
                st.info("No recommendations data available")
                return

            # Create DataFrame with only available columns
            df = pd.DataFrame(recommendations)
            display_columns = [
                'priority', 'description', 'target_date', 'status', 'impact'
            ]

            # Filter to only include columns that exist
            available_columns = [col for col in display_columns if col in df.columns]

            if not available_columns:
                st.warning("No valid columns found in recommendations data")
                return

            display_df = df[available_columns]

            # Apply styling
            styled_df = display_df.style.apply(lambda x: [
                'background-color: rgba(255,77,77,0.3)' if v == 'High' else
                'background-color: rgba(255,166,77,0.3)' if v == 'Medium' else
                'background-color: rgba(77,166,255,0.3)' if v == 'Low' else ''
                for v in x
            ], subset=['priority'] if 'priority' in available_columns else [])

            st.dataframe(styled_df)

        except Exception as e:
            logger.error(f"Error displaying recommendations: {str(e)}")
            st.error(f"Error displaying recommendations table: {str(e)}")

    def generate_interactive_dashboard(self) -> Dict[str, Any]:
        """Generate all visualizations for dashboard with explanations"""
        try:
            # Generate visualizations and explanations
            severity_fig, severity_explanation = self.create_severity_distribution()
            coverage_fig, coverage_explanation = self.create_coverage_radar()
            gap_fig, gap_explanation = self.create_gap_heatmap()
            timeline_fig, timeline_explanation = self.create_timeline_view()

            return {
                'figures': {
                    'severity_distribution': severity_fig,
                    'coverage_radar': coverage_fig,
                    'gap_heatmap': gap_fig,
                    'timeline_view': timeline_fig
                },
                'explanations': {
                    'severity_distribution': severity_explanation,
                    'coverage_radar': coverage_explanation,
                    'gap_heatmap': gap_explanation,
                    'timeline_view': timeline_explanation
                }
            }
        except Exception as e:
            self.logger.error(f"Error generating dashboard: {str(e)}")
            return {}


@dataclass
class GapFindings:
    """Data class for gap analysis findings"""
    category: str
    severity: str
    description: str
    current_state: Any
    expected_state: Any
    impact: str
    recommendations: List[str]


class GapDataValidator:
    """Validates and generates gap analysis data"""

    def __init__(self, driver):
        self.driver = driver
        logger = logging.getLogger(__name__)

        try:
            with self.driver.session() as session:
                result = session.run("RETURN 1 as test")
                test_value = result.single()
                if test_value is None or test_value.get('test') != 1:
                    raise Exception("Failed to verify Neo4j connection")
                logger.info("Successfully initialized GapDataValidator with Neo4j connection")
        except Exception as e:
            logger.error(f"Error initializing GapDataValidator: {str(e)}")
            logger.error(traceback.format_exc())
            raise

    def validate_data_connections(self) -> Dict[str, bool]:
        """Validate if all required relationships exist"""
        with self.driver.session() as session:
            # Check principle-requirement connections
            principle_req = session.run("""
                MATCH (p:Principle)-[:HAS_REQUIREMENT]->(r:Requirement) 
                RETURN COUNT(*) as count
            """).single()['count']

            # Check requirement-control connections
            req_control = session.run("""
                MATCH (r:Requirement)-[:IMPLEMENTED_BY]->(c:Control)
                RETURN COUNT(*) as count
            """).single()['count']

            # Check control-activity connections
            control_activity = session.run("""
                MATCH (c:Control)-[:MONITORS]->(a:Activity)
                RETURN COUNT(*) as count
            """).single()['count']

            return {
                'principle_requirement_exists': principle_req > 0,
                'requirement_control_exists': req_control > 0,
                'control_activity_exists': control_activity > 0
            }

    def ensure_gap_data(self):
        """Create realistic gap data matching existing Neo4j structure"""
        with self.driver.session() as session:
            # Reset existing mock data
            session.run("""
                MATCH (r:Requirement)
                SET r.status = null,
                    r.severity = null,
                    r.gap_type = null
            """)

            # Create gaps for EXEC principles (we have 4)
            session.run("""
                MATCH (p:Principle)
                WHERE p.code STARTS WITH 'EXEC'
                WITH p
                MATCH (p)-[:HAS_REQUIREMENT]->(r:Requirement)
                WITH r, rand() as rnd
                WHERE rnd < 0.6  // Create gaps for 60% of EXEC requirements
                SET r.status = 'NOT_IMPLEMENTED',
                    r.severity = CASE 
                        WHEN rnd < 0.2 THEN 'High'   // 20% High
                        WHEN rnd < 0.5 THEN 'Medium' // 30% Medium
                        ELSE 'Low'                   // 10% Low
                    END,
                    r.gap_type = 'Regulatory Compliance'
            """)

            # Create gaps for RISK principles (we have 2)
            session.run("""
                MATCH (p:Principle)
                WHERE p.code STARTS WITH 'RISK'
                WITH p
                MATCH (p)-[:HAS_REQUIREMENT]->(r:Requirement)
                WITH r, rand() as rnd
                WHERE rnd < 0.5  // Create gaps for 50% of RISK requirements
                SET r.status = 'NOT_IMPLEMENTED',
                    r.severity = CASE 
                        WHEN rnd < 0.3 THEN 'High'   // 30% High
                        WHEN rnd < 0.7 THEN 'Medium' // 40% Medium
                        ELSE 'Low'                   // 30% Low
                    END,
                    r.gap_type = 'Risk Control'
            """)

            # Create unmonitored activities (out of 35 total)
            session.run("""
                MATCH (a:Activity)
                WITH a, rand() as rnd
                WHERE rnd < 0.3  // 30% of 35 activities = ~10 unmonitored
                SET a.monitored = false,
                    a.completion_rate = 0.6 + (rand() * 0.2)  // 60-80% completion
            """)

            # Modify control-activity relationships (8 controls)
            session.run("""
                MATCH (c:Control)-[r:MONITORS]->(a:Activity)
                WITH c, r, a, rand() as rnd
                WHERE rnd < 0.25  // Disconnect 25% of existing control relationships
                DELETE r
                SET a.control_gap = true
            """)

            # Return gap statistics
            return session.run("""
                MATCH (r:Requirement)
                WHERE r.status = 'NOT_IMPLEMENTED'
                WITH r.severity as severity, r.gap_type as type, COUNT(*) as count
                RETURN collect({
                    severity: severity,
                    type: type,
                    count: count
                }) as gaps
            """).single()['gaps']

    def _get_default_metrics(self) -> Dict:
        """Get default metrics when query fails"""
        return {
            'regulatory_coverage': 0.0,
            'process_adherence': 0.0,
            'control_effectiveness': 0.0,
            'risk_coverage': 0.0
        }

    def get_gap_metrics(self) -> Dict:
        """Get metrics based on actual Neo4j state with enhanced error handling"""
        logger.info("Getting gap metrics from Neo4j")

        try:
            with self.driver.session() as session:
                # Modified query to handle missing relationships
                query_result = session.run("""
                    // Calculate requirement coverage
                    OPTIONAL MATCH (r:Requirement)
                    WITH COALESCE(COUNT(r), 0) as total_requirements,
                         COALESCE(COUNT(r.status), 0) as gap_requirements

                    // Calculate activity monitoring
                    OPTIONAL MATCH (a:Activity)
                    WITH total_requirements, gap_requirements,
                         COALESCE(COUNT(a), 0) as total_activities,
                         COALESCE(COUNT(a.monitored), 0) as unmonitored_activities

                    // Calculate control effectiveness
                    OPTIONAL MATCH (c:Control)-[:MONITORS]->(a:Activity)
                    WITH total_requirements, gap_requirements,
                         total_activities, unmonitored_activities,
                         COALESCE(COUNT(DISTINCT c), 0) as active_controls

                    RETURN {
                        regulatory_coverage: CASE 
                            WHEN total_requirements > 0 
                            THEN round(((total_requirements - gap_requirements) * 100.0) / total_requirements, 1)
                            ELSE 0.0 
                        END,
                        process_adherence: CASE 
                            WHEN total_activities > 0 
                            THEN round(((total_activities - unmonitored_activities) * 100.0) / total_activities, 1)
                            ELSE 0.0 
                        END,
                        control_effectiveness: CASE 
                            WHEN active_controls > 0 
                            THEN round((active_controls * 100.0) / 8, 1)
                            ELSE 0.0 
                        END,
                        risk_coverage: 0.0
                    } as metrics
                """)

                result = query_result.single()
                if result is None:
                    logger.error("No metrics returned from Neo4j query - query returned no results")
                    return self._get_default_metrics()

                metrics = result.get('metrics')
                if metrics is None:
                    logger.error("Metrics not found in query result")
                    return self._get_default_metrics()

                logger.info(f"Successfully retrieved metrics: {metrics}")
                return metrics

        except Exception as e:
            logger.error(f"Error getting gap metrics: {str(e)}")
            logger.error(traceback.format_exc())
            return self._get_default_metrics()


