DELIMITER $$

CREATE PROCEDURE UpdateEvent(
    IN event_id INT,
    IN title VARCHAR(100),
    IN description TEXT,
    IN event_date DATETIME,
    IN location VARCHAR(255)
)
BEGIN
    UPDATE Event
    SET title = title, description = description, event_date = event_date, location = location
    WHERE event_id = event_id;
END $$

DELIMITER ;