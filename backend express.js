const express = require('express')
const {open} = require('sqlite')
const sqlite3 = require('sqlite3')
const path = require('path')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()
app.use(express.json())

const dbPath = path.join(__dirname, 'twitterClone.db')
let db = null

// Initialize database connection
const initializeDbAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    })
    app.listen(3000, () =>
      console.log('Server running at http://localhost:3000/'),
    )
  } catch (e) {
    console.error(`DB Error: ${e.message}`)
    process.exit(1)
  }
}

initializeDbAndServer()

// Helper function to retrieve IDs of people the user follows
const getFollowingPeopleIdsOfUser = async username => {
  const query = `
    SELECT following_user_id 
    FROM follower 
    INNER JOIN user ON user.user_id = follower.follower_user_id 
    WHERE user.username = ?;
  `
  const followingPeople = await db.all(query, [username])
  return followingPeople.map(person => person.following_user_id)
}

// Middleware for JWT authentication
const authenticateToken = (request, response, next) => {
  const authHeader = request.headers['authorization']
  const jwtToken = authHeader?.split(' ')[1]

  if (!jwtToken) {
    return response.status(401).send('Invalid JWT Token')
  }

  jwt.verify(jwtToken, 'SECRET_KEY', (error, payload) => {
    if (error) {
      return response.status(401).send('Invalid JWT Token')
    }
    request.username = payload.username
    request.userId = payload.userId
    next()
  })
}

// Middleware to verify access to a specific tweet
const tweetAccessTokenVerification = async (request, response, next) => {
  const {userId} = request
  const {tweetId} = request.params

  const query = `
    SELECT tweet_id 
    FROM tweet 
    INNER JOIN follower 
    ON tweet.user_id = follower.following_user_id 
    WHERE tweet.tweet_id = ? AND follower.follower_user_id = ?;
  `
  const tweet = await db.get(query, [tweetId, userId])
  if (!tweet) {
    return response.status(401).send('Invalid Request')
  }
  next()
}

// API 1: Register
app.post('/register/', async (request, response) => {
  const {username, password, name, gender} = request.body

  const userExistsQuery = `SELECT * FROM user WHERE username = ?;`
  const existingUser = await db.get(userExistsQuery, [username])

  if (existingUser) {
    return response.status(400).send('User already exists')
  }

  if (password.length < 6) {
    return response.status(400).send('Password is too short')
  }

  const hashedPassword = await bcrypt.hash(password, 10)
  const createUserQuery = `
    INSERT INTO user (username, password, name, gender)
    VALUES (?, ?, ?, ?);
  `
  await db.run(createUserQuery, [username, hashedPassword, name, gender])
  response.send('User created successfully')
})

// API 2: Login
app.post('/login/', async (request, response) => {
  const {username, password} = request.body

  const query = `SELECT * FROM user WHERE username = ?;`
  const user = await db.get(query, [username])

  if (!user) {
    return response.status(400).send('Invalid user')
  }

  const isPasswordCorrect = await bcrypt.compare(password, user.password)
  if (!isPasswordCorrect) {
    return response.status(400).send('Invalid password')
  }

  const payload = {username, userId: user.user_id}
  const jwtToken = jwt.sign(payload, 'SECRET_KEY')
  response.send({jwtToken})
})

// API 3: Get user's tweet feed
app.get('/user/tweets/feed/', authenticateToken, async (request, response) => {
  const {username} = request
  const followingIds = await getFollowingPeopleIdsOfUser(username)

  const query = `
    SELECT username, tweet, date_time AS dateTime 
    FROM user 
    INNER JOIN tweet ON user.user_id = tweet.user_id 
    WHERE user.user_id IN (${followingIds.join(',')}) 
    ORDER BY date_time DESC 
    LIMIT 4;
  `
  const tweets = await db.all(query)
  response.send(tweets)
})

// API 4: Get following users
app.get('/user/following/', authenticateToken, async (request, response) => {
  const {userId} = request

  const query = `
    SELECT name 
    FROM user 
    INNER JOIN follower ON user.user_id = follower.following_user_id 
    WHERE follower.follower_user_id = ?;
  `
  const following = await db.all(query, [userId])
  response.send(following)
})

// API 5: Get followers
app.get('/user/followers/', authenticateToken, async (request, response) => {
  const {userId} = request

  const query = `
    SELECT name 
    FROM user 
    INNER JOIN follower ON user.user_id = follower.follower_user_id 
    WHERE follower.following_user_id = ?;
  `
  const followers = await db.all(query, [userId])
  response.send(followers)
})

// API 6: Get tweet details
app.get(
  '/tweets/:tweetId/',
  authenticateToken,
  tweetAccessTokenVerification,
  async (request, response) => {
    const {tweetId} = request.params

    const query = `
      SELECT tweet, 
      (SELECT COUNT(*) FROM like WHERE tweet_id = ?) AS likes, 
      (SELECT COUNT(*) FROM reply WHERE tweet_id = ?) AS replies, 
      date_time AS dateTime 
      FROM tweet 
      WHERE tweet_id = ?;
    `
    const tweet = await db.get(query, [tweetId, tweetId, tweetId])
    response.send(tweet)
  },
)

// API 7: Get likes of a tweet
app.get(
  '/tweets/:tweetId/likes/',
  authenticateToken,
  tweetAccessTokenVerification,
  async (request, response) => {
    const {tweetId} = request.params
    const getLikesQuery = `
      SELECT username 
      FROM user 
      INNER JOIN like ON user.user_id = like.user_id 
      WHERE tweet_id = ?;
    `
    const likedUsers = await db.all(getLikesQuery, [tweetId])
    const usersArray = likedUsers.map(i => i.username)
    response.send({likes: usersArray})
  },
)

// API 8: Get replies of a tweet
app.get(
  '/tweets/:tweetId/replies/',
  authenticateToken,
  tweetAccessTokenVerification,
  async (request, response) => {
    const {tweetId} = request.params
    const getRepliedQuery = `
      SELECT name, reply 
      FROM user 
      INNER JOIN reply ON user.user_id = reply.user_id 
      WHERE tweet_id = ?;
    `
    const repliedUser = await db.all(getRepliedQuery, [tweetId])
    response.send({replies: repliedUser})
  },
)

// API 9: Get user's tweets
app.get('/user/tweets/', authenticateToken, async (request, response) => {
  const {userId} = request
  const getTweetsQuery = `
    SELECT tweet, 
           COUNT(DISTINCT like.like_id) AS likes, 
           COUNT(DISTINCT reply.reply_id) AS replies, 
           date_time AS dateTime 
    FROM tweet 
    LEFT JOIN like ON tweet.tweet_id = like.tweet_id 
    LEFT JOIN reply ON tweet.tweet_id = reply.tweet_id 
    WHERE tweet.user_id = ? 
    GROUP BY tweet.tweet_id;
  `
  const tweets = await db.all(getTweetsQuery, [userId])
  response.send(tweets)
})

// API 10: Create a tweet
app.post('/user/tweets/', authenticateToken, async (request, response) => {
  const {tweet} = request.body
  const {userId} = request
  const dateTime = new Date().toISOString().substring(0, 19).replace('T', ' ')
  const createTweetQuery = `
    INSERT INTO tweet (tweet, user_id, date_time)
    VALUES (?, ?, ?);
  `
  await db.run(createTweetQuery, [tweet, userId, dateTime])
  response.send('Created a Tweet')
})

// API 11: Delete a tweet
app.delete(
  '/tweets/:tweetId/',
  authenticateToken,
  async (request, response) => {
    const {tweetId} = request.params
    const {userId} = request

    const getTheTweetQuery = `
    SELECT * FROM tweet 
    WHERE user_id = ? AND tweet_id = ?;
  `
    const tweet = await db.get(getTheTweetQuery, [userId, tweetId])

    if (!tweet) {
      response.status(401).send('Invalid Request')
    } else {
      const deleteTweetQuery = `
      DELETE FROM tweet 
      WHERE tweet_id = ?;
    `
      await db.run(deleteTweetQuery, [tweetId])
      response.send('Tweet Removed')
    }
  },
)

// Export the app
module.exports = app

