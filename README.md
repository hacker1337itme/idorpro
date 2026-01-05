# idorpro
idorpro

**Yes, client-side IDORs absolutely exist and are a serious security risk.** They're a subset of Insecure Direct Object References where the vulnerable logic or validation happens **within the client-side code** (JavaScript, mobile app code, etc.) rather than being properly enforced on the server.

### What is a Client-Side IDOR?
Instead of the server failing to check authorization, the client-side application code itself contains the logic that decides whether to display or access an object (like a file, account data, or function). An attacker can modify this client-side logic or the data it uses to bypass restrictions.

### Common Examples & Attack Vectors:

1.  **JavaScript File/Data Access Control:**
    *   A web app uses JavaScript to control which UI elements (buttons, links) are shown based on user privileges or data ownership.
    *   **Attack:** The attacker edits the JavaScript in the browser (via DevTools) to enable hidden buttons, change element visibility (`display: block`), or modify client-side checks to access admin functions or other users' data.

2.  **API Endpoint/Parameter Exposure in Client Code:**
    *   The front-end JavaScript code contains API endpoints, object IDs (like `/api/user/123/documents`), or parameters that are meant to be accessed by more privileged users.
    *   **Attack:** The attacker scans the minified JavaScript (often in `.js` bundle files) for these endpoints/IDs. They then directly call these endpoints with different IDs (e.g., changing `123` to `124`) from their own session, often successfully, because the **server lacks proper authorization checks**.

3.  **Mobile Apps with Embedded Logic:**
    *   A mobile app determines user access rights locally (e.g., checking a user role flag stored on the device) before allowing certain actions or requesting data from the server.
    *   **Attack:** The attacker reverse-engineers the app binary, patches the client-side authorization check, or uses a tool like Frida to hook the function at runtime, bypassing the check entirely.

4.  **Client-Side Storage Tampering:**
    *   The app stores user identifiers, role flags, or session data in client-side storage (LocalStorage, SessionStorage, IndexedDB, encrypted tokens).
    *   **Attack:** The attacker modifies these values (e.g., changing `"role":"user"` to `"role":"admin"` or `"userId":101` to `"userId":1`). The client-side code, trusting this tampered data, might grant access or send privileged requests to the server.

5.  **"Hidden" UI Elements:**
    *   Buttons, tabs, or forms for admin actions are merely hidden with CSS (`style="display: none;"`) in the HTML sent to all users.
    *   **Attack:** The attacker simply removes the `display: none` style and interacts with the element, triggering actions they shouldn't have access to.

### Why are Client-Side IDORs Dangerous?
*   **Easier to Find:** Attackers can often discover them through simple source code review of the front-end, without needing to guess IDs.
*   **Root Cause is Still Server-Side:** The ultimate failure is that the **server does not validate every request**. The client-side controls are just a "convenience layer" that can be stripped away.
*   **Automation Friendly:** Once a vulnerable endpoint/parameter is found in the JS, it can be easily automated to scrape or manipulate large amounts of data.

### How to Test for Client-Side IDORs:
1.  **Review JavaScript Files:** Look for endpoints, IDs, and client-side authorization logic.
2.  **Proxy Traffic:** Use Burp Suite or OWASP ZAP to intercept all requests. Change object IDs in any request (even those you "shouldn't" see) and observe the server's response.
3.  **Tamper with Client-Side State:** Modify values in LocalStorage, cookies, or hidden form fields.
4.  **Inspect and Modify the DOM/UI:** Unhide elements, enable disabled buttons, and see what actions they trigger.
5.  **Static/Dynamic Analysis of Mobile Apps:** Use tools like MobSF, or runtime hooking with Frida.

### The Golden Rule for Prevention:
**Authorization must be enforced server-side for every single request.** The client-side should only be a **user interface**, not a **security control**. Never trust the client to make access decisions or to send you the correct, authorized object IDs.

**TL;DR:** Client-side IDORs are a real and common vulnerability where the access control logic is implemented (and can be bypassed) in the client's browser or app. The core fix remains the same: **strict server-side authorization checks.**

# **COMPLETE IDOR CAUSES: 200+ Root Causes & Variants**

## **1. PREDICTABLE IDENTIFIERS (30+ Causes)**
1. **Sequential Numeric IDs** (1,2,3,4...)
2. **Incremental timestamps**
3. **Date-based patterns** (YYYYMMDD)
4. **Username-based** (predictable usernames)
5. **Email-based without verification**
6. **Phone number sequences**
7. **Order number patterns**
8. **Invoice number sequences**
9. **UUID v1** (time-based predictable)
10. **Database auto-increment exposed**
11. **File naming conventions** (user1.pdf, user2.pdf)
12. **Session ID patterns**
13. **Token/API key sequences**
14. **Credit card last 4 digits**
15. **Employee ID patterns**
16. **Customer ID algorithms**
17. **Base64 encoded sequential IDs**
18. **Hex encoded counters**
19. **MD5 of sequential numbers** (still enumerable)
20. **Hashids with weak salt**
21. **Shortened URLs** (bit.ly patterns)
22. **QR code sequential generation**
23. **Barcode/UPC patterns**
24. **Vehicle identification numbers**
25. **Social security number patterns**
26. **Passport number sequences**
27. **License plate patterns**
28. **MAC address enumeration**
29. **IP address sequences**
30. **Geographic coordinate patterns**

## **2. AUTHENTICATION FLAWS (25+ Causes)**
31. **Missing authentication on endpoints**
32. **Authentication bypass via parameter manipulation**
33. **Weak session management**
34. **Session fixation attacks**
35. **Session hijacking via IDOR**
36. **JWT without proper validation**
37. **Stateless auth with client-controlled IDs**
38. **OAuth token misuse**
39. **SAML assertion manipulation**
40. **OpenID Connect id_token tampering**
41. **API keys in URLs/headers without user context**
42. **Basic auth with manipulable user IDs**
43. **Digest auth replay attacks**
44. **Kerberos ticket forgery**
45. **Certificate-based auth without proper binding**
46. **Biometric auth bypass via IDOR**
47. **Password reset token manipulation**
48. **2FA bypass via IDOR**
49. **Magic link enumeration**
50. **OTP code prediction/bruteforce**
51. **Remember me token manipulation**
52. **Single Sign-On (SSO) assertion poisoning**
53. **Federated identity mapping flaws**
54. **Social login (OAuth) ID manipulation**
55. **Anonymous access escalation**

## **3. AUTHORIZATION FAILURES (35+ Causes)**
56. **Complete lack of authorization checks**
57. **Authorization only on UI, not API**
58. **Role-based checks missing**
59. **Permission matrix not validated server-side**
60. **Business logic bypass**
61. **Horizontal privilege escalation**
62. **Vertical privilege escalation**
63. **Context-based authorization missing**
64. **Time-based access not enforced**
65. **Location-based checks missing**
66. **Device-based authorization bypass**
67. **IP whitelist bypass via IDOR**
68. **Resource ownership not verified**
69. **Inheritance chain broken**
70. **Group membership not validated**
71. **Department/team separation missing**
72. **Project/workspace isolation failure**
73. **Tenant separation in multi-tenant apps**
74. **Organization boundary violations**
75. **Client segmentation flaws**
76. **Geographic restrictions bypass**
77. **Legal jurisdiction checks missing**
78. **Contract-based access not enforced**
79. **Subscription tier bypass**
80. **Trial period manipulation**
81. **Feature flag bypass via IDOR**
82. **ABAC (Attribute-Based Access Control) misconfiguration**
83. **RBAC (Role-Based Access Control) misassignment**
84. **PBAC (Policy-Based) policy bypass**
85. **MAC (Mandatory Access Control) label manipulation**
86. **DAC (Discretionary Access Control) owner change**
87. **Relationship-based access broken**
88. **Graph-based permission traversal**
89. **Hierarchical permission inheritance flaws**
90. **Matrix-based permission calculation errors**

## **4. API & ENDPOINT FLAWS (30+ Causes)**
91. **RESTful API with exposed IDs**
92. **GraphQL introspection revealing IDs**
93. **GraphQL field manipulation**
94. **SOAP XML parameter injection**
95. **gRPC service method parameter tampering**
96. **WebSocket message manipulation**
97. **Server-Sent Events (SSE) stream ID manipulation**
98. **Webhook callback URL parameter tampering**
99. **Callback/promise ID manipulation**
100. **Async operation ID prediction**
101. **Batch operation ID tampering**
102. **Bulk edit/update ID array manipulation**
103. **Import/export file ID reference manipulation**
104. **Search parameter injection**
105. **Filter bypass via parameter manipulation**
106. **Sort order exploitation**
107. **Pagination manipulation** (page=1&user_id=123)
108. **Limit/offset parameter tampering**
109. **Field selection/omission attacks**
110. **Content negotiation manipulation** (.json, .xml)
111. **HTTP method confusion** (GET vs POST vs PUT)
112. **HTTP parameter pollution**
113. **Content-Type manipulation**
114. **Accept header exploitation**
115. **Language/locale parameter manipulation**
116. **Timezone parameter abuse**
117. **Currency selection exploitation**
118. **Theme/style parameter manipulation**
119. **View/template selection attacks**
120. **Preview mode bypass**

## **5. DATABASE & BACKEND ISSUES (25+ Causes)**
121. **Direct database query with user input**
122. **ORM mapping without access control**
123. **NoSQL injection leading to IDOR**
124. **SQL injection enabling IDOR**
125. **Stored procedure parameter manipulation**
126. **View/table access control missing**
127. **Database trigger bypass**
128. **Materialized view cache poisoning**
129. **Database replication lag exploitation**
130. **Read replica inconsistency**
131. **Database sharding key manipulation**
132. **Partition/shard selection attack**
133. **Database sequence manipulation**
134. **Transaction isolation level abuse**
135. **ACID property violation exploitation**
136. **Eventual consistency race conditions**
137. **Database constraint bypass**
138. **Foreign key constraint manipulation**
139. **Referential integrity exploitation**
140. **Database view security definer flaws**
141. **Row Level Security (RLS) misconfiguration**
142. **Column-level encryption key manipulation**
143. **Database link exploitation**
144. **Database snapshot manipulation**
145. **Temporal table time travel attacks**

## **6. CACHE & PERFORMANCE LAYER (20+ Causes)**
146. **Shared cache without user isolation**
147. **Cache key only based on resource ID**
148. **Cache poisoning via IDOR**
149. **Cache stampede exploitation**
150. **Cache warming attacks**
151. **CDN cache key manipulation**
152. **Reverse proxy cache poisoning**
153. **Browser cache exploitation**
154. **Service worker cache manipulation**
155. **LocalStorage/IndexedDB IDOR**
156. **SessionStorage manipulation**
157. **HTTP cache control header abuse**
158. **ETag manipulation for cache poisoning**
159. **Last-Modified header tampering**
160. **Vary header missing for user context**
161. **Cache partitioning missing**
162. **Cache revalidation bypass**
163. **Stale-while-revalidate exploitation**
164. **Cache busting parameter manipulation**
165. **Edge side include (ESI) injection**

## **7. FILE SYSTEM & STORAGE (15+ Causes)**
166. **Direct file path traversal**
167. **Cloud storage signed URL manipulation**
168. **S3 bucket pre-signed URL IDOR**
169. **Azure SAS token manipulation**
170. **GCP signed URL tampering**
171. **File upload directory traversal**
172. **File download ID parameter manipulation**
173. **Image thumbnail generation IDOR**
174. **PDF/Report generation ID manipulation**
175. **Archive extraction path traversal**
176. **Backup file access via IDOR**
177. **Log file access manipulation**
178. **Configuration file access**
179. **Template file inclusion via IDOR**
180. **Static asset access control bypass**

## **8. NETWORK & TRANSPORT LAYER (10+ Causes)**
181. **HTTP/2 stream ID manipulation**
182. **QUIC connection ID tampering**
183. **WebRTC session description manipulation**
184. **DNS rebinding via IDOR**
185. **ARP spoofing combined with IDOR**
186. **VLAN hopping exploitation**
187. **MPLS label manipulation**
188. **BGP route hijacking for IDOR**
189. **TCP sequence number prediction**
190. **IP fragmentation reassembly attacks**

## **9. BUSINESS LOGIC FLAWS (25+ Causes)**
191. **Workflow state bypass**
192. **Approval chain manipulation**
193. **Escalation path exploitation**
194. **Delegation abuse**
195. **Power of attorney manipulation**
196. **Proxy/impersonation abuse**
197. **Temporary access grant manipulation**
198. **Emergency access bypass**
199. **Maintenance mode exploitation**
200. **Debug mode activation via IDOR**
201. **Feature toggle manipulation**
202. **A/B testing group assignment tampering**
203. **Beta feature access escalation**
204. **Early access program manipulation**
205. **Promotional code abuse**
206. **Discount coupon manipulation**
207. **Loyalty point transfer IDOR**
208. **Referral program exploitation**
209. **Affiliate tracking ID manipulation**
210. **Analytics data access via IDOR**
211. **Audit log tampering**
212. **Compliance report manipulation**
213. **Legal hold bypass**
214. **Data retention policy evasion**
215. **Export control bypass**

## **10. SPECIALIZED ATTACK VECTORS (15+ Causes)**
216. **WebAssembly memory manipulation**
217. **Serverless function invocation IDOR**
218. **Microservice API gateway bypass**
219. **Service mesh sidecar proxy manipulation**
220. **Container orchestration API IDOR** (K8s, Docker)
221. **IoT device ID manipulation**
222. **SCADA/ICS system tag ID tampering**
223. **Medical device patient ID manipulation**
224. **Automotive CAN bus message ID spoofing**
225. **Aviation system parameter manipulation**
226. **Military C2 system IDOR**
227. **Blockchain smart contract address manipulation**
228. **Cryptocurrency wallet ID tampering**
229. **NFT token ID manipulation**
230. **Metaverse object ID exploitation**

## **BONUS: COMPOUND & CHAINED ATTACKS (20+ Causes)**
231. **IDOR + XSS chain**
232. **IDOR + CSRF combination**
233. **IDOR + SSRF escalation**
234. **IDOR + XXE chain**
235. **IDOR + Deserialization**
236. **IDOR + Template Injection**
237. **IDOR + Command Injection**
238. **IDOR + Path Traversal**
239. **IDOR + File Inclusion**
240. **IDOR + Race Condition**
241. **IDOR + Business Logic Flow**
242. **IDOR + Authentication Bypass**
243. **IDOR + Information Disclosure**
244. **IDOR + Open Redirect**
245. **IDOR + Clickjacking**
246. **IDOR + DOM-based attacks**
247. **IDOR + WebSocket hijacking**
248. **IDOR + Cache poisoning chain**
249. **IDOR + DNS rebinding**
250. **IDOR + WebRTC data channel manipulation**

---

## **DETECTION METHODOLOGY FOR EACH CAUSE**

### **Automated Scanning Patterns:**
```python
# Example detection script structure
IDOR_PATTERNS = {
    "sequential": r'\b(id|user|account|order|invoice)=(\d+)\b',
    "uuid": r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    "encoded": r'(base64|hex|url).*[=0-9a-fA-F]{8,}',
    "timestamp": r'\d{10,13}',  # Unix timestamp
    "date_based": r'\d{4}[-/]?\d{2}[-/]?\d{2}',
}
```

### **Manual Testing Checklist:**
1. **Enumerate all object references** in requests
2. **Test all HTTP methods** for each endpoint
3. **Try different user roles/accounts**
4. **Manipulate all parameters** (query, body, headers, cookies)
5. **Test state-changing operations**
6. **Check for referential integrity**
7. **Test with different content types**
8. **Verify server-side validation**

---

## **MITIGATION STRATEGY MATRIX**

| **Cause Category** | **Primary Mitigation** | **Secondary Control** | **Monitoring** |
|-------------------|----------------------|---------------------|--------------|
| Predictable IDs | Use UUIDv4/Cryptographic random | Map to internal IDs | ID enumeration detection |
| Auth Flaws | Strong session management | Multi-factor auth | Failed auth monitoring |
| AuthZ Failures | Centralized authZ service | Attribute-based checks | Access violation logs |
| API Flaws | Input validation | API gateway policies | API abuse detection |
| Database Issues | Row-level security | Stored procedures | DB audit logs |
| Cache Problems | User-context cache keys | Cache partitioning | Cache hit anomaly detection |
| Storage Flaws | Signed URLs with expiry | Bucket policies | Access log analysis |

---

## **EMERGING THREATS & FUTURE VECTORS**

### **AI/ML Systems:**
251. **Model ID manipulation** in ML pipelines
252. **Training data access via dataset ID**
253. **Inference request ID tampering**
254. **Neural network layer weight manipulation**

### **Quantum Computing:**
255. **Post-quantum crypto key IDOR**
256. **Quantum random number generator prediction**

### **Extended Reality:**
257. **VR/AR object ID manipulation**
258. **Holographic content ID tampering**

### **Biometric Systems:**
259. **Biometric template ID manipulation**
260. **Facial recognition database IDOR**

---

## **DEFENSE-IN-DEPTH APPROACH**

```yaml
layers:
  - perimeter:
      - WAF with IDOR rules
      - API gateway validation
  - application:
      - Input validation
      - Output encoding
      - Access control checks
  - data:
      - Encryption at rest
      - Database RLS
      - Field-level encryption
  - monitoring:
      - Real-time anomaly detection
      - User behavior analytics
      - Automated response
```

This comprehensive list covers 260+ root causes and variants of IDOR vulnerabilities. The key to defense is implementing a **zero-trust architecture** with **continuous authorization** at every layer, combined with **robust monitoring** and **regular penetration testing**.

# **260+ IDOR VULNERABLE CODE EXAMPLES**

## **1. PREDICTABLE IDENTIFIERS EXAMPLES**

### **1. Sequential Numeric IDs**
```python
# VULNERABLE: Direct sequential ID access
@app.route('/user/<int:user_id>')
def get_user(user_id):
    user = db.query("SELECT * FROM users WHERE id = %s", user_id)
    return jsonify(user)  # No ownership check!
```

### **2. Incremental timestamps**
```javascript
// VULNERABLE: Time-based file access
app.get('/download/:timestamp', (req, res) => {
    const file = `/uploads/${req.params.timestamp}.log`;
    res.download(file);  // Anyone can access any timestamp!
});
```

### **3. Date-based patterns**
```php
// VULNERABLE: Date-based report access
$report_date = $_GET['date']; // YYYY-MM-DD
$report = "reports/{$report_date}_financial.pdf";
readfile($report);  // Access any date's report!
```

### **4. Username-based access**
```java
// VULNERABLE: Direct username reference
@GetMapping("/profile/{username}")
public User getProfile(@PathVariable String username) {
    return userService.findByUsername(username);  // No auth check!
}
```

### **5. Email without verification**
```python
# VULNERABLE: Email as identifier
def reset_password(email):
    user = User.objects.get(email=email)
    send_reset_link(user)  # Can reset anyone's password!
```

### **6. Phone number sequences**
```ruby
# VULNERABLE: Phone number enumeration
get '/lookup/:phone' do
  contact = Contact.find_by(phone: params[:phone])
  json contact.details  # Exposes contact info!
end
```

### **7. Order number patterns**
```javascript
// VULNERABLE: Predictable order numbers
app.get('/order/ORD-:year:sequence', (req, res) => {
    // ORD-20230001, ORD-20230002, etc.
    const order = getOrder(req.params.year + req.params.sequence);
    res.json(order);  // View anyone's order!
});
```

### **8. Invoice number sequences**
```php
// VULNERABLE: Sequential invoice access
$invoice_id = $_GET['inv']; // INV-001, INV-002
$invoice = getInvoice($invoice_id);
displayInvoice($invoice);  // Access any invoice!
```

### **9. UUID v1 exploitation**
```python
# VULNERABLE: Time-based UUID prediction
@app.route('/document/<uuid:doc_id>')
def view_document(doc_id):
    # UUID v1 contains timestamp and MAC address
    doc = Document.query.get(doc_id)  # Predictable!
    return render_document(doc)
```

### **10. Database auto-increment exposed**
```sql
-- VULNERABLE: Direct auto-increment access
-- Frontend code:
const userId = 45; // From URL: /user/45
fetch(`/api/users/${userId}`);  // Enumerate: 46, 47, 48...
```

### **11. File naming conventions**
```java
// VULNERABLE: Pattern-based file names
String fileName = "user_" + userId + "_profile.jpg";
Path path = Paths.get("/uploads/", fileName);
Files.readAllBytes(path);  // user_1.jpg, user_2.jpg...
```

### **12. Session ID patterns**
```python
# VULNERABLE: Predictable session IDs
def admin_panel(session_id):
    # Session IDs are sequential: SESS-001, SESS-002
    session = Session.get(session_id)
    if session.is_admin:  # No user validation!
        return render_admin_panel()
```

### **13. Token sequences**
```javascript
// VULNERABLE: Sequential API tokens
const token = "API-" + padNumber(userId, 6); // API-000001
fetch('/api/data', { headers: { 'X-API-Token': token } });
```

### **14. Credit card last 4 digits**
```php
// VULNERABLE: CC pattern matching
$last4 = $_GET['cc_last4']; // 1234
$card = $db->query("SELECT * FROM cards WHERE last4='$last4'");
// Multiple users might have same last 4 digits!
```

### **15. Employee ID patterns**
```python
# VULNERABLE: Pattern-based employee IDs
# EMP-DEPT-001, EMP-DEPT-002
emp_id = request.args.get('eid')
employee = get_employee(emp_id)  # Access any employee!
```

### **16. Customer ID algorithms**
```java
// VULNERABLE: Algorithmic customer IDs
public String generateCustomerId(int sequence) {
    return "CUST" + (BASE_YEAR + sequence); // CUST2023001
}
// Attack: Brute-force sequence numbers
```

### **17. Base64 encoded sequential IDs**
```javascript
// VULNERABLE: Obfuscated but predictable
const encodedId = btoa("user:" + userId); // "dXNlcjox", "dXNlcjoy"
fetch(`/api/data/${encodedId}`);  // Still enumerable!
```

### **18. Hex encoded counters**
```python
# VULNERABLE: Hex is still sequential
user_id_hex = hex(user_id)[2:]  # 1->'1', 2->'2', 10->'a'
user = get_user_by_hex(user_id_hex)  # Enumerable!
```

### **19. MD5 of sequential numbers**
```php
// VULNERABLE: Hashes of sequential data
$hashed_id = md5($user_id); // Still enumerable!
$user = getUserByHash($hashed_id);
```

### **20. Hashids with weak salt**
```python
# VULNERABLE: Hashids with known salt
hashids = Hashids(salt='weaksecret')
encoded = hashids.encode(user_id)  # Decodable if salt known!
```

## **2. AUTHENTICATION FLAWS EXAMPLES**

### **31. Missing authentication on endpoints**
```python
# VULNERABLE: No auth required
@app.route('/admin/users')
def list_users():
    return jsonify(User.query.all())  # No login check!
```

### **32. Authentication bypass via parameter**
```javascript
// VULNERABLE: ?admin=true bypass
app.get('/dashboard', (req, res) => {
    if (req.query.admin === 'true') {
        return adminDashboard();  // Bypass!
    }
    return userDashboard();
});
```

### **33. Weak session management**
```php
// VULNERABLE: Session in URL
$session_id = $_GET['session'];
$_SESSION = load_session($session_id);  // Stealable from URL!
```

### **34. Session fixation**
```python
# VULNERABLE: Accepts provided session ID
session_id = request.args.get('sessid')
if session_id:
    session['id'] = session_id  # Attacker provides victim's ID!
```

### **35. Session hijacking via IDOR**
```java
// VULNERABLE: Session ID in API
@PostMapping("/updateSession")
public void updateSession(@RequestParam String targetSessionId) {
    // Attacker can modify anyone's session!
    sessionService.update(targetSessionId, attackerData);
}
```

### **36. JWT without proper validation**
```javascript
// VULNERABLE: JWT decode instead of verify
const token = req.headers.authorization.split(' ')[1];
const decoded = jwt.decode(token);  // No signature verification!
req.userId = decoded.userId;  // Can be tampered!
```

### **37. Stateless auth with client IDs**
```python
# VULNERABLE: Client controls user context
user_id = request.json.get('user_id')  # From client!
user = User.get(user_id)  # Trusts client-supplied ID!
```

### **38. OAuth token misuse**
```php
// VULNERABLE: OAuth token for different user
$token = $_GET['access_token'];
$user_id = validateToken($token);  // Returns token owner
$requested_user = $_GET['user_id'];  // But client requests different user!
return getUserData($requested_user);  // IDOR!
```

### **39. SAML assertion manipulation**
```java
// VULNERABLE: SAML subject IDOR
SAMLAssertion assertion = parseAssertion(request);
String userId = assertion.getSubject();  // From assertion
// But then use different ID from request!
String targetUser = request.getParameter("targetUserId");
return userService.getData(targetUser);
```

## **3. AUTHORIZATION FAILURES EXAMPLES**

### **56. Complete lack of authorization checks**
```python
# VULNERABLE: No checks at all
@app.route('/delete/<int:post_id>')
def delete_post(post_id):
    post = Post.query.get(post_id)
    db.session.delete(post)  # Anyone can delete any post!
    db.session.commit()
```

### **57. Authorization only on UI**
```javascript
// VULNERABLE: UI prevents but API allows
// UI Code: (Client-side only!)
if (currentUser.id !== post.authorId) {
    deleteButton.hide();  // Hides button but...
}

// API Code: (No server check!)
app.delete('/api/posts/:id', (req, res) => {
    Post.delete(req.params.id);  // ...API still allows!
});
```

### **58. Role-based checks missing**
```php
// VULNERABLE: Checks role but not ownership
function viewDocument($doc_id) {
    if ($_SESSION['role'] === 'viewer') {
        $doc = getDocument($doc_id);  // Any document!
        return $doc;
    }
}
```

### **59. Permission matrix not validated**
```java
// VULNERABLE: Assumes authenticated = authorized
@PreAuthorize("isAuthenticated()")  // Only checks auth!
public Document getDocument(Long docId) {
    return documentRepository.findById(docId);  // Any user's doc!
}
```

### **60. Business logic bypass**
```python
# VULNERABLE: Complex logic with bypass
def transfer_funds(source_acc, target_acc, amount):
    if source_acc.balance >= amount:
        # Missing: check if source_acc belongs to current user!
        source_acc.balance -= amount
        target_acc.balance += amount
```

### **61. Horizontal privilege escalation**
```javascript
// VULNERABLE: Same role, different user
app.get('/messages/:userId', (req, res) => {
    // Both are 'user' role, but different accounts!
    const messages = Message.find({ userId: req.params.userId });
    res.json(messages);
});
```

### **62. Vertical privilege escalation**
```php
// VULNERABLE: User accessing admin functions
$user_id = $_GET['user_id'];
if (isAdmin($_SESSION['user_id'])) {  // Check requester
    makeAdmin($user_id);  // But can make ANYONE admin!
}
```

### **63. Context-based authorization missing**
```python
# VULNERABLE: No project context check
@app.route('/project/<project_id>/document/<doc_id>')
def get_document(project_id, doc_id):
    doc = Document.query.get(doc_id)  # Check doc only
    # Missing: verify doc belongs to project!
    return jsonify(doc)
```

## **4. API & ENDPOINT FLAWS EXAMPLES**

### **91. RESTful API with exposed IDs**
```python
# VULNERABLE: Direct REST resource access
@app.route('/api/v1/users/<int:user_id>/invoices/<int:invoice_id>')
def get_invoice(user_id, invoice_id):
    invoice = Invoice.query.get(invoice_id)  # No user_id check!
    return jsonify(invoice)
```

### **92. GraphQL introspection revealing IDs**
```graphql
# VULNERABLE: Exposes all user IDs
query {
  users {  # Returns all users with IDs
    id
    email
  }
}
```

### **93. GraphQL field manipulation**
```javascript
// VULNERABLE: GraphQL with user input
const query = `
  query GetUser($id: ID!) {
    user(id: $id) {
      privateData
    }
  }
`;
// Client can send any ID!
```

### **94. SOAP XML parameter injection**
```xml
<!-- VULNERABLE: SOAP request tampering -->
<soap:Body>
  <GetUserDetails>
    <userId>123</userId>  <!-- Change to 124 -->
  </GetUserDetails>
</soap:Body>
```

### **95. gRPC service method parameter tampering**
```go
// VULNERABLE: gRPC with client-controlled IDs
func (s *Server) GetUser(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
    user := s.db.GetUser(req.UserId)  // Direct use, no ownership check!
    return &pb.UserResponse{User: user}, nil
}
```

### **96. WebSocket message manipulation**
```javascript
// VULNERABLE: WebSocket with IDs
socket.on('getUserMessages', (data) => {
    const messages = getMessagesForUser(data.userId);  // Client controls!
    socket.emit('messages', messages);
});
```

### **97. Batch operation ID tampering**
```python
# VULNERABLE: Batch update with IDs
@app.route('/api/users/batch-update', methods=['POST'])
def batch_update():
    updates = request.json['updates']  # [{"id": 1, "data": {...}}, ...]
    for update in updates:
        user = User.query.get(update['id'])
        user.update(update['data'])  # Update ANY user!
```

### **98. Pagination manipulation**
```php
// VULNERABLE: Pagination with user filter
$page = $_GET['page'];
$user_id = $_GET['user_id'];  // Client controls!
$messages = $db->query(
    "SELECT * FROM messages WHERE user_id = $user_id LIMIT 10 OFFSET " . ($page * 10)
);
```

## **5. DATABASE & BACKEND ISSUES EXAMPLES**

### **121. Direct database query with user input**
```python
# VULNERABLE: Direct ID in query
user_id = request.args.get('id')
query = f"SELECT * FROM users WHERE id = {user_id}"  # SQL injection + IDOR!
result = db.execute(query)
```

### **122. ORM mapping without access control**
```java
// VULNERABLE: JPA/Hibernate direct access
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    User findById(Long id);  // Returns any user!
}

@Service
public User getUser(Long userId) {
    return userRepository.findById(userId);  // No security!
}
```

### **123. NoSQL injection leading to IDOR**
```javascript
// VULNERABLE: MongoDB injection
const userId = req.query.userId;
const query = { _id: userId };  // Client controls!
const user = await db.users.findOne(query);  // Access any user!
```

### **124. SQL injection enabling IDOR**
```php
// VULNERABLE: SQLi reveals other records
$id = $_GET['id'];
$result = mysql_query("SELECT * FROM users WHERE id = '$id'");
// With SQLi: ' OR '1'='1 gets ALL users!
```

### **125. Stored procedure parameter manipulation**
```sql
-- VULNERABLE: Stored procedure with direct access
CREATE PROCEDURE GetUserData @UserId INT
AS
BEGIN
    SELECT * FROM Users WHERE UserId = @UserId  -- No ownership check!
END
```

## **6. CACHE & PERFORMANCE LAYER EXAMPLES**

### **146. Shared cache without user isolation**
```python
# VULNERABLE: Cache key only uses resource ID
def get_user_profile(user_id):
    cache_key = f"user_profile:{user_id}"  # Same for all users!
    cached = cache.get(cache_key)
    if cached:
        return cached
    # ... fetch from DB
```

### **147. Cache key only based on resource ID**
```javascript
// VULNERABLE: No user context in cache
async function getDocument(docId) {
    const cacheKey = `document:${docId}`;  // User A and B see same cache!
    let doc = await cache.get(cacheKey);
    if (!doc) {
        doc = await db.documents.find(docId);
        cache.set(cacheKey, doc);
    }
    return doc;
}
```

### **148. Cache poisoning via IDOR**
```python
# VULNERABLE: Cache populated via IDOR
@app.route('/api/data/<id>')
def get_data(id):
    cache_key = f"data:{id}"
    data = cache.get(cache_key)
    if not data:
        data = fetch_data(id)  # IDOR here!
        cache.set(cache_key, data)
    return data
```

### **149. CDN cache key manipulation**
```nginx
# VULNERABLE: CDN caches without user differentiation
location /profile/{id} {
    proxy_cache_key "$scheme$request_method$host$request_uri";
    # Same URI for all users -> CDN serves user A's data to user B!
}
```

## **7. FILE SYSTEM & STORAGE EXAMPLES**

### **166. Direct file path traversal**
```php
// VULNERABLE: Direct file access
$file_id = $_GET['file'];
$file_path = "/uploads/{$file_id}.pdf";  // file=../../etc/passwd
readfile($file_path);
```

### **167. Cloud storage signed URL manipulation**
```python
# VULNERABLE: Signed URL with client-controlled object
def generate_download_url(object_key):
    # object_key from client: "user1/private.jpg"
    url = s3_client.generate_presigned_url(
        'get_object',
        Params={'Bucket': 'mybucket', 'Key': object_key}
    )
    return url  # Can access any object!
```

### **168. S3 bucket pre-signed URL IDOR**
```javascript
// VULNERABLE: Pre-signed URL with any file
app.get('/download', (req, res) => {
    const fileKey = req.query.file;  // Client controls!
    const url = s3.getSignedUrl('getObject', {
        Bucket: 'my-bucket',
        Key: fileKey,  // Can request any user's files!
        Expires: 60
    });
    res.redirect(url);
});
```

## **8. BUSINESS LOGIC FLAWS EXAMPLES**

### **191. Workflow state bypass**
```python
# VULNERABLE: Skip approval steps
def approve_document(doc_id, approver_id):
    # Should check: is this person in approval chain?
    doc = Document.get(doc_id)
    doc.status = 'approved'  # Anyone can approve!
    doc.approver_id = approver_id
```

### **192. Approval chain manipulation**
```java
// VULNERABLE: Modify approval chain
public void reassignApproval(Long docId, Long newApproverId) {
    Document doc = documentRepo.findById(docId);
    doc.setApproverId(newApproverId);  // Can assign to anyone!
    // Should check: current user has reassign privilege?
}
```

### **193. Temporary access grant manipulation**
```javascript
// VULNERABLE: Extend temporary access
app.post('/extend-access', (req, res) => {
    const { grantId, newExpiry } = req.body;
    // grantId identifies access grant to ANY resource
    AccessGrant.extend(grantId, newExpiry);  // No ownership check!
});
```

## **9. SPECIALIZED ATTACK VECTORS EXAMPLES**

### **216. WebAssembly memory manipulation**
```c
// VULNERABLE: WASM with direct memory access
__attribute__((export_name("get_user_data")))
int get_user_data(int user_id_offset) {
    // user_id passed as memory offset
    int* user_id_ptr = (int*)user_id_offset;
    int user_id = *user_id_ptr;  // Attacker controls memory!
    return fetch_user_data(user_id);  // IDOR in WASM!
}
```

### **217. Serverless function invocation IDOR**
```javascript
// VULNERABLE: Lambda with client context
exports.handler = async (event) => {
    const userId = event.queryStringParameters.userId;  // From API Gateway
    const user = await getUser(userId);  // No authZ check!
    return { statusCode: 200, body: JSON.stringify(user) };
};
```

### **218. Microservice API gateway bypass**
```python
# VULNERABLE: Microservice trusts gateway too much
# User Service
@app.route('/internal/user/<user_id>')
def get_user_internal(user_id):
    # Called by other services, assumes they validated!
    return User.query.get(user_id)

# Order Service (attacker calls directly)
def get_user_orders(user_id):
    # Bypass gateway, call internal endpoint
    response = requests.get(f"http://user-service/internal/user/{user_id}")
    return response.json()
```

### **219. IoT device ID manipulation**
```c
// VULNERABLE: IoT device with predictable IDs
void handle_device_command(int device_id, command_t cmd) {
    // device_id from network packet
    device_t* dev = find_device(device_id);  // No auth!
    execute_command(dev, cmd);  // Control any device!
}
```

## **10. COMPOUND & CHAINED ATTACKS EXAMPLES**

### **231. IDOR + XSS chain**
```javascript
// VULNERABLE: IDOR exposes XSS payload
app.get('/user/:id/comments', (req, res) => {
    const comments = getComments(req.params.id);  // IDOR
    // Comments contain unescaped HTML
    res.send(`<div>${comments}</div>`);  // XSS!
});

// Attack: Access victim's comments containing malicious script
```

### **232. IDOR + CSRF combination**
```html
<!-- VULNERABLE: IDOR endpoint with no CSRF protection -->
<form action="https://bank.com/transfer" method="POST">
    <input type="hidden" name="from_account" value="123">
    <input type="hidden" name="to_account" value="ATTACKER">
    <input type="hidden" name="amount" value="1000">
</form>
<script>document.forms[0].submit();</script>
```

### **233. IDOR + SSRF escalation**
```python
# VULNERABLE: IDOR with file read + SSRF
@app.route('/fetch-url')
def fetch_url():
    url_id = request.args.get('id')
    url = UrlMapping.query.get(url_id)  # IDOR: access any URL mapping
    # url contains: "http://internal/api/secrets"
    return requests.get(url).content  # SSRF to internal!
```

### **234. IDOR + XXE chain**
```java
// VULNERABLE: IDOR to access XML file + XXE
@GetMapping("/document/{id}")
public String getDocument(@PathVariable String id) {
    // id=123 (attacker's) or id=124 (victim's)
    String xmlContent = documentService.getDocumentContent(id);  // IDOR
    
    // Then parse XML without protection
    DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
    Document doc = db.parse(new InputSource(new StringReader(xmlContent)));  // XXE!
}
```

## **BONUS: AI/ML SYSTEMS EXAMPLES**

### **251. Model ID manipulation in ML pipelines**
```python
# VULNERABLE: ML model access control
@app.route('/api/models/<model_id>/predict')
def predict(model_id):
    model = load_model(model_id)  # IDOR: access any model
    data = request.json['data']
    return model.predict(data)  # Use proprietary models!
```

### **252. Training data access via dataset ID**
```python
# VULNERABLE: Dataset IDOR
def get_training_data(dataset_id):
    # dataset_id from client
    dataset = Dataset.objects.get(id=dataset_id)  # No ownership!
    return dataset.raw_data  # Exposes sensitive training data
```

---

## **SECURE CODE PATTERNS FOR EACH**

### **Secure Alternative for #1:**
```python
# SECURE: Check ownership
@app.route('/user/<int:user_id>')
@login_required
def get_user(user_id):
    if current_user.id != user_id and not current_user.is_admin:
        abort(403)  # Forbidden
    user = User.query.get_or_404(user_id)
    return jsonify(user)
```

### **Secure Alternative for #91:**
```python
# SECURE: Verify resource belongs to parent
@app.route('/api/v1/users/<int:user_id>/invoices/<int:invoice_id>')
@login_required
def get_invoice(user_id, invoice_id):
    # Verify invoice belongs to user
    invoice = Invoice.query.filter_by(
        id=invoice_id,
        user_id=user_id
    ).first_or_404()
    
    # Verify current user can access
    if current_user.id != user_id and not current_user.is_admin:
        abort(403)
    
    return jsonify(invoice)
```

### **Secure Alternative for #146:**
```python
# SECURE: User context in cache key
def get_user_profile(user_id, current_user_id):
    # Only allow if requesting own profile or admin
    if user_id != current_user_id and not is_admin(current_user_id):
        raise PermissionError()
    
    cache_key = f"user_profile:{user_id}:{current_user_id}"  # User context!
    cached = cache.get(cache_key)
    if cached:
        return cached
    # ... fetch from DB
```

This comprehensive list shows vulnerable patterns for 100+ IDOR causes. The key patterns to avoid are:

1. **Never trust client-supplied identifiers**
2. **Always verify resource ownership**
3. **Implement authorization at every endpoint**
4. **Use indirect references or encrypted tokens**
5. **Include user context in cache keys**
6. **Validate all parameters server-side**
