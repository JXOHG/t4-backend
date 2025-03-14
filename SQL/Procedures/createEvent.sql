DELIMITER $$

CREATE PROCEDURE CreateEvent(
    IN title VARCHAR(100),
    IN description TEXT,
    IN event_date DATETIME,
    IN location VARCHAR(255)
)
BEGIN
    INSERT INTO Event (title, description, event_date, location)
    VALUES (title, description, event_date, location);
END $$

DELIMITER ;