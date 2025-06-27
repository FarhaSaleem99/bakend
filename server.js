// server.js
const express = require('express');
const cors = require('cors');
require('dotenv').config(); // Loads .env file


const { protect, authorize } = require('./middleware/authMiddleware'); // Adjust path if needed

const sql = require('mssql'); // For SQL Server
const dbConfig = require('./config/dbConfig'); // We created this in Step 2.D
const bcrypt = require('bcryptjs'); // For password hashing
const jwt = require('jsonwebtoken'); // For creating tokens

const app = express();
const PORT = process.env.PORT || 5001;

app.use(cors()); // Allow cross-origin requests
app.use(express.json()); // Allow backend to read JSON from requests

app.get('/', (req, res) => {
  res.send('Quiz Backend is Running!');
});

app.listen(PORT, () => {
  console.log(`Backend server started on http://localhost:${PORT}`);
});


// server.js (add these parts)

// ... (your existing Express setup) ...

// Test DB Connection (can be removed or moved to a dedicated function later)
async function testDbConnection() {
    try {
        let pool = await sql.connect(dbConfig);
        console.log("Successfully connected to Azure SQL Database!");
        // You can run a simple query here if you want
        // const result = await pool.request().query('SELECT GETDATE() as CurrentTime');
        // console.log('Current DB Time:', result.recordset[0].CurrentTime);
        pool.close(); // Close the pool if just testing
    } catch (err) {
        console.error("Database Connection Failed! Bad Config: ", err);
    }
}
testDbConnection(); // Call the test function

// ... (app.listen) ...



// 1. REGISTER A NEW USER
app.post('/api/auth/register', async (req, res) => {
    const { fullName, email, password, role } = req.body;

    // Basic validation (you can add more complex validation later)
    if (!fullName || !email || !password || !role) {
        return res.status(400).json({ message: 'All fields are required (fullName, email, password, role).' });
    }
    if (password.length < 6) {
        return res.status(400).json({ message: 'Password must be at least 6 characters long.' });
    }
    if (!['student', 'teacher', 'admin'].includes(role.toLowerCase())) {
        return res.status(400).json({ message: "Role must be 'student', 'teacher', or 'admin'." });
    }

    try {
        const pool = await sql.connect(dbConfig);

        // Check if user already exists
        const userExistsResult = await pool.request()
            .input('Email', sql.NVarChar, email)
            .query('SELECT UserID FROM Users WHERE Email = @Email');

        if (userExistsResult.recordset.length > 0) {
            return res.status(409).json({ message: 'User with this email already exists.' }); // 409 Conflict
        }

        // Hash the password
        const salt = await bcrypt.genSalt(10); // Generate a salt
        const passwordHash = await bcrypt.hash(password, salt); // Hash the password

        // Insert new user into the database
        await pool.request()
            .input('FullName', sql.NVarChar, fullName)
            .input('Email', sql.NVarChar, email)
            .input('PasswordHash', sql.NVarChar, passwordHash)
            .input('Role', sql.NVarChar, role.toLowerCase())
            .query('INSERT INTO Users (FullName, Email, PasswordHash, Role) VALUES (@FullName, @Email, @PasswordHash, @Role)');

        res.status(201).json({ message: 'User registered successfully!' });

    } catch (err) {
        console.error('Error during registration:', err);
        res.status(500).json({ message: 'Server error during registration.', error: err.message });
    } finally {
        sql.close(); // Close the connection if it was opened
    }
});


// 2. LOGIN AN EXISTING USER
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required.' });
    }

    try {
        const pool = await sql.connect(dbConfig);

        // Find user by email
        const userResult = await pool.request()
            .input('Email', sql.NVarChar, email)
            .query('SELECT UserID, FullName, Email, PasswordHash, Role FROM Users WHERE Email = @Email');

        if (userResult.recordset.length === 0) {
            return res.status(401).json({ message: 'Invalid credentials. User not found.' }); // Unauthorized
        }

        const user = userResult.recordset[0];

        // Compare submitted password with stored hashed password
        const isMatch = await bcrypt.compare(password, user.PasswordHash);

        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials. Password incorrect.' }); // Unauthorized
        }

        // User is authenticated, create a JWT
        const payload = {
            user: {
                id: user.UserID,
                role: user.Role
                // You can add more non-sensitive info if needed
            }
        };

        jwt.sign(
            payload,
            process.env.JWT_SECRET, // Your secret key from .env
            { expiresIn: '1h' }, // Token expires in 1 hour (adjust as needed)
            (err, token) => {
                if (err) throw err;
                res.json({
                    token,
                    user: { // Send back some user info for the frontend
                        id: user.UserID,
                        fullName: user.FullName,
                        email: user.Email,
                        role: user.Role
                    }
                });
            }
        );

    } catch (err) {
        console.error('Error during login:', err);
        res.status(500).json({ message: 'Server error during login.', error: err.message });
    } finally {
        // sql.close(); // Managed by pool, usually not closed after every request here
                     // unless you are not using pooling effectively or have specific needs.
                     // For single connection outside of a pool, yes.
                     // For 'await sql.connect(dbConfig)', the pool is often reused.
                     // Let's assume the pool handles it. If issues, add explicit close.
    }
});


// ... (app.listen at the very end) ...
// === QUIZ MANAGEMENT ROUTES ===

// 1. CREATE A NEW QUIZ (Protected: Teacher or Admin)
app.post('/api/quizzes', protect, authorize('teacher', 'admin'), async (req, res) => {
    const { title, description, questions } = req.body;
    const creatorUserId = req.user.id; // Get user ID from the authenticated user

    // Basic validation
    if (!title || !questions || !Array.isArray(questions) || questions.length === 0) {
        return res.status(400).json({ message: 'Title and at least one question are required.' });
    }
    for (const q of questions) {
        if (!q.questionText || !q.options || !Array.isArray(q.options) || q.options.length < 2 || q.correctAnswerIndex === undefined) {
            return res.status(400).json({ message: 'Each question must have text, at least 2 options, and a correctAnswerIndex.' });
        }
        if (q.correctAnswerIndex < 0 || q.correctAnswerIndex >= q.options.length) {
            return res.status(400).json({ message: `Invalid correctAnswerIndex for question: "${q.questionText}"` });
        }
    }

    const pool = await sql.connect(dbConfig);
    const transaction = new sql.Transaction(pool); // Use a transaction for multiple inserts

    try {
        await transaction.begin();

        // Insert into Quizzes table
        const quizResult = await new sql.Request(transaction)
            .input('Title', sql.NVarChar, title)
            .input('Description', sql.NVarChar, description || null) // Handle optional description
            .input('CreatorUserID', sql.Int, creatorUserId)
            .query('INSERT INTO Quizzes (Title, Description, CreatorUserID) OUTPUT INSERTED.QuizID VALUES (@Title, @Description, @CreatorUserID)');
        
        const quizId = quizResult.recordset[0].QuizID;

        // Insert questions and options
        for (const question of questions) {
            const questionResult = await new sql.Request(transaction)
                .input('QuizID', sql.Int, quizId)
                .input('QuestionText', sql.NVarChar, question.questionText)
                .input('QuestionType', sql.NVarChar, question.questionType || 'multiple-choice') // Default type
                .query('INSERT INTO Questions (QuizID, QuestionText, QuestionType) OUTPUT INSERTED.QuestionID VALUES (@QuizID, @QuestionText, @QuestionType)');
            
            const questionId = questionResult.recordset[0].QuestionID;

            for (let i = 0; i < question.options.length; i++) {
                await new sql.Request(transaction)
                    .input('QuestionID', sql.Int, questionId)
                    .input('OptionText', sql.NVarChar, question.options[i])
                    .input('IsCorrect', sql.Bit, i === question.correctAnswerIndex ? 1 : 0)
                    .query('INSERT INTO Options (QuestionID, OptionText, IsCorrect) VALUES (@QuestionID, @OptionText, @IsCorrect)');
            }
        }

        await transaction.commit();
        res.status(201).json({ message: 'Quiz created successfully!', quizId: quizId });

    } catch (err) {
        await transaction.rollback(); // Rollback in case of error
        console.error('Error creating quiz:', err);
        res.status(500).json({ message: 'Server error creating quiz.', error: err.message });
    } finally {
        // Pool is managed, usually not closed here if you plan more operations.
        // If you are done with all operations in this request, and not using persistent pool sql.close();
    }
});


// server.js
// ...

// 2. GET ALL QUIZZES (Public)
app.get('/api/quizzes', async (req, res) => {
    try {
        const pool = await sql.connect(dbConfig);
        const result = await pool.request()
            .query(`
                SELECT 
                    q.QuizID, q.Title, q.Description, 
                    u.FullName as CreatorName, 
                    (SELECT COUNT(*) FROM Questions WHERE QuizID = q.QuizID) as QuestionCount
                FROM Quizzes q
                JOIN Users u ON q.CreatorUserID = u.UserID
                ORDER BY q.CreatedAt DESC
            `);
        res.json(result.recordset);
    } catch (err) {
        console.error('Error fetching quizzes:', err);
        res.status(500).json({ message: 'Server error fetching quizzes.', error: err.message });
    }
});

// server.js
// ...

// 3. GET A SINGLE QUIZ BY ID (Public, but content might vary by role later if needed)
app.get('/api/quizzes/:quizId', async (req, res) => {
    const { quizId } = req.params;

    try {
        const pool = await sql.connect(dbConfig);

        // Get Quiz Details
        const quizResult = await pool.request()
            .input('QuizID', sql.Int, quizId)
            .query('SELECT QuizID, Title, Description, CreatorUserID FROM Quizzes WHERE QuizID = @QuizID');

        if (quizResult.recordset.length === 0) {
            return res.status(404).json({ message: 'Quiz not found.' });
        }
        const quiz = quizResult.recordset[0];

        // Get Questions for the Quiz
        const questionsResult = await pool.request()
            .input('QuizID', sql.Int, quizId)
            .query('SELECT QuestionID, QuestionText, QuestionType FROM Questions WHERE QuizID = @QuizID');
        
        quiz.questions = [];

        for (const question of questionsResult.recordset) {
            const optionsResult = await pool.request()
                .input('QuestionID', sql.Int, question.QuestionID)
                .query('SELECT OptionID, OptionText, IsCorrect FROM Options WHERE QuestionID = @QuestionID');
            
            // For students, you might want to omit IsCorrect or send it differently
            // For now, let's include it, assuming this endpoint might also be used by creators/admins
            // or the quiz taking logic on frontend will not show it.
            // A better approach for students is a separate endpoint or role-based filtering here.
            question.options = optionsResult.recordset.map(opt => ({
                optionId: opt.OptionID,
                text: opt.OptionText
                // If sending to student, DO NOT send opt.IsCorrect here
            }));
            quiz.questions.push(question);
        }

        res.json(quiz);

    } catch (err) {
        console.error(`Error fetching quiz ${quizId}:`, err);
        res.status(500).json({ message: 'Server error fetching quiz details.', error: err.message });
    }
});

// server.js
// ...

// 4. UPDATE AN EXISTING QUIZ (Protected: Teacher or Admin - typically quiz creator or admin)
app.put('/api/quizzes/:quizId', protect, authorize('teacher', 'admin'), async (req, res) => {
    const { quizId } = req.params;
    const { title, description, questions } = req.body;
    const editorUserId = req.user.id;

    // Basic validation (similar to create)
    if (!title || !questions || !Array.isArray(questions) || questions.length === 0) {
        return res.status(400).json({ message: 'Title and at least one question are required for update.' });
    }
    // ... (add full question validation as in POST /api/quizzes) ...

    const pool = await sql.connect(dbConfig);
    const transaction = new sql.Transaction(pool);

    try {
        await transaction.begin();

        // Optional: Check if the user is the creator or an admin
        const quizCheck = await new sql.Request(transaction)
            .input('QuizID', sql.Int, quizId)
            .query('SELECT CreatorUserID FROM Quizzes WHERE QuizID = @QuizID');
        
        if (quizCheck.recordset.length === 0) {
            await transaction.rollback();
            return res.status(404).json({ message: 'Quiz not found for update.' });
        }
        // if (quizCheck.recordset[0].CreatorUserID !== editorUserId && req.user.role !== 'admin') {
        //     await transaction.rollback();
        //     return res.status(403).json({ message: 'Not authorized to edit this quiz.' });
        // }

        // Update Quizzes table
        await new sql.Request(transaction)
            .input('QuizID', sql.Int, quizId)
            .input('Title', sql.NVarChar, title)
            .input('Description', sql.NVarChar, description || null)
            .query('UPDATE Quizzes SET Title = @Title, Description = @Description WHERE QuizID = @QuizID');

        // Delete existing questions and options for this quiz (simplest approach for full update)
        // First delete options (due to foreign key constraints)
        await new sql.Request(transaction)
            .input('QuizID', sql.Int, quizId)
            .query('DELETE FROM Options WHERE QuestionID IN (SELECT QuestionID FROM Questions WHERE QuizID = @QuizID)');
        
        await new sql.Request(transaction)
            .input('QuizID', sql.Int, quizId)
            .query('DELETE FROM Questions WHERE QuizID = @QuizID');

        // Re-insert questions and options (same logic as create)
        for (const question of questions) {
            const questionResult = await new sql.Request(transaction)
                .input('QuizID', sql.Int, quizId)
                .input('QuestionText', sql.NVarChar, question.questionText)
                .input('QuestionType', sql.NVarChar, question.questionType || 'multiple-choice')
                .query('INSERT INTO Questions (QuizID, QuestionText, QuestionType) OUTPUT INSERTED.QuestionID VALUES (@QuizID, @QuestionText, @QuestionType)');
            
            const questionId = questionResult.recordset[0].QuestionID;

            for (let i = 0; i < question.options.length; i++) {
                await new sql.Request(transaction)
                    .input('QuestionID', sql.Int, questionId)
                    .input('OptionText', sql.NVarChar, question.options[i])
                    .input('IsCorrect', sql.Bit, i === question.correctAnswerIndex ? 1 : 0)
                    .query('INSERT INTO Options (QuestionID, OptionText, IsCorrect) VALUES (@QuestionID, @OptionText, @IsCorrect)');
            }
        }

        await transaction.commit();
        res.json({ message: 'Quiz updated successfully!', quizId: parseInt(quizId) });

    } catch (err) {
        await transaction.rollback();
        console.error(`Error updating quiz ${quizId}:`, err);
        res.status(500).json({ message: 'Server error updating quiz.', error: err.message });
    }
});

// server.js
// ...

// 5. DELETE A QUIZ (Protected: Teacher or Admin - typically quiz creator or admin)
app.delete('/api/quizzes/:quizId', protect, authorize('teacher', 'admin'), async (req, res) => {
    const { quizId } = req.params;
    const deleterUserId = req.user.id;

    const pool = await sql.connect(dbConfig);
    const transaction = new sql.Transaction(pool);

    try {
        await transaction.begin();

        // Optional: Check if the user is the creator or an admin
        const quizCheck = await new sql.Request(transaction)
            .input('QuizID', sql.Int, quizId)
            .query('SELECT CreatorUserID FROM Quizzes WHERE QuizID = @QuizID');
        
        if (quizCheck.recordset.length === 0) {
            await transaction.rollback();
            return res.status(404).json({ message: 'Quiz not found for deletion.' });
        }
        // if (quizCheck.recordset[0].CreatorUserID !== deleterUserId && req.user.role !== 'admin') {
        //     await transaction.rollback();
        //     return res.status(403).json({ message: 'Not authorized to delete this quiz.' });
        // }

        // Delete associated records first due to foreign key constraints
        // 1. UserQuizResults (if any student took this quiz)
        await new sql.Request(transaction)
            .input('QuizID', sql.Int, quizId)
            .query('DELETE FROM UserQuizResults WHERE QuizID = @QuizID');

        // 2. Options
        await new sql.Request(transaction)
            .input('QuizID', sql.Int, quizId)
            .query('DELETE FROM Options WHERE QuestionID IN (SELECT QuestionID FROM Questions WHERE QuizID = @QuizID)');

        // 3. Questions
        await new sql.Request(transaction)
            .input('QuizID', sql.Int, quizId)
            .query('DELETE FROM Questions WHERE QuizID = @QuizID');

        // 4. Finally, the Quiz itself
        const deleteResult = await new sql.Request(transaction)
            .input('QuizID', sql.Int, quizId)
            .query('DELETE FROM Quizzes WHERE QuizID = @QuizID');

        if (deleteResult.rowsAffected[0] === 0) {
            // Should have been caught by the quizCheck, but as a safeguard
            await transaction.rollback();
            return res.status(404).json({ message: 'Quiz not found or already deleted.'});
        }
        
        await transaction.commit();
        res.json({ message: 'Quiz deleted successfully.' });

    } catch (err) {
        await transaction.rollback();
        console.error(`Error deleting quiz ${quizId}:`, err);
        res.status(500).json({ message: 'Server error deleting quiz.', error: err.message });
    }
});


// server.js

// ... (quiz management routes from Step 4) ...

// === QUIZ SUBMISSION ROUTE ===

// SUBMIT QUIZ ANSWERS (Protected: Student)
app.post('/api/quizzes/:quizId/submit', protect, authorize('student'), async (req, res) => {
    const { quizId } = req.params;
    const userId = req.user.id; // Get student's ID from the authenticated user (JWT)
    const { answers, timeTakenSeconds } = req.body; // Expecting answers as an array of objects e.g., [{ questionId: X, selectedOptionId: Y }] or [{ questionId: X, selectedOptionIndex: Y_idx }]

    // Basic validation
    if (!answers || !Array.isArray(answers) || answers.length === 0) {
        return res.status(400).json({ message: 'Answers array is required and cannot be empty.' });
    }
    if (timeTakenSeconds === undefined || typeof timeTakenSeconds !== 'number') {
        return res.status(400).json({ message: 'timeTakenSeconds (number) is required.' });
    }

    const pool = await sql.connect(dbConfig);
    const transaction = new sql.Transaction(pool);

    try {
        await transaction.begin();

        // 1. Fetch all questions and their correct options for the given quizId
        const questionsAndCorrectOptions = await new sql.Request(transaction)
            .input('QuizID', sql.Int, quizId)
            .query(`
                SELECT 
                    q.QuestionID, 
                    o.OptionID as CorrectOptionID,
                    o.OptionText as CorrectOptionText -- Optional, for logging or detailed results
                FROM Questions q
                JOIN Options o ON q.QuestionID = o.QuestionID
                WHERE q.QuizID = @QuizID AND o.IsCorrect = 1
            `);

        if (questionsAndCorrectOptions.recordset.length === 0) {
            await transaction.rollback();
            return res.status(404).json({ message: 'Quiz not found or has no questions with correct answers defined.' });
        }

        // Create a map for easy lookup of correct answers
        const correctAnswersMap = new Map();
        questionsAndCorrectOptions.recordset.forEach(row => {
            correctAnswersMap.set(row.QuestionID, row.CorrectOptionID);
        });

        // 2. Calculate the score
        let score = 0;
        const totalQuestionsInQuiz = correctAnswersMap.size; // Or fetch count separately

        // The 'answers' from req.body needs to align with how your frontend sends data.
        // Assuming 'answers' is an array of objects: { questionId: number, selectedOptionId: number }
        // Or, if frontend sends selected option *index*, you need to fetch OptionIDs based on index first.
        // For simplicity, let's assume frontend sends { questionId, selectedOptionId }
        // Let's also assume the frontend might not send an answer for every question if it uses radio buttons.

        // To be more robust, iterate through the questions of the quiz, not just the submitted answers.
        const allQuizQuestions = await new sql.Request(transaction)
            .input('QuizID', sql.Int, quizId)
            .query('SELECT QuestionID FROM Questions WHERE QuizID = @QuizID');

        for (const quizQuestion of allQuizQuestions.recordset) {
            const studentAnswer = answers.find(a => a.questionId === quizQuestion.QuestionID);
            if (studentAnswer && correctAnswersMap.get(quizQuestion.QuestionID) === studentAnswer.selectedOptionId) {
                score++;
            }
        }
        
        const percentageScore = (score / totalQuestionsInQuiz) * 100;


        // 3. Save the result to UserQuizResults table
        // Convert the received answers array to a JSON string for storage
        const answersGivenJSON = JSON.stringify(answers);

        await new sql.Request(transaction)
            .input('UserID', sql.Int, userId)
            .input('QuizID', sql.Int, quizId)
            .input('Score', sql.Decimal(5, 2), percentageScore) // Storing as percentage
            .input('TimeTakenSeconds', sql.Int, timeTakenSeconds)
            .input('AnswersGivenJSON', sql.NVarChar(sql.MAX), answersGivenJSON)
            .query(`
                INSERT INTO UserQuizResults (UserID, QuizID, Score, TimeTakenSeconds, AnswersGivenJSON)
                VALUES (@UserID, @QuizID, @Score, @TimeTakenSeconds, @AnswersGivenJSON)
            `);

        await transaction.commit();

        res.status(200).json({
            message: 'Quiz submitted successfully!',
            quizId: parseInt(quizId),
            userId: userId,
            score: score,
            totalQuestions: totalQuestionsInQuiz,
            percentageScore: parseFloat(percentageScore.toFixed(2)),
            timeTakenSeconds: timeTakenSeconds
        });

    } catch (err) {
        if (transaction.active) { // Check if transaction is active before trying to rollback
            await transaction.rollback();
        }
        console.error(`Error submitting quiz ${quizId} for user ${userId}:`, err);
        res.status(500).json({ message: 'Server error submitting quiz.', error: err.message });
    }
});





