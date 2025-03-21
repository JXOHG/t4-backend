DELIMITER $$

CREATE PROCEDURE updateRegistration(
    IN registration_id INT,
    IN new_user_id INT,
    IN new_event_id INT
)
BEGIN
    -- Validate the new_user_id and new_event_id exist
    IF EXISTS (SELECT 1 FROM User WHERE user_id = new_user_id) 
    AND EXISTS (SELECT 1 FROM Event WHERE event_id = new_event_id) THEN
        
        UPDATE Manages 
        SET 
            user_id = new_user_id,
            event_id = new_event_id
        WHERE 
            registration_id = registration_id;
        
    ELSE
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Invalid user_id or event_id';
    END IF;
END $$

DELIMITER ;